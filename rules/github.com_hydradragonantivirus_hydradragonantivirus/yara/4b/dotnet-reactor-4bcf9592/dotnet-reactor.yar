import "pe"
rule DotNET_Reactor: Eziriz {
  meta:
    author = "_pusher_"
    date   = "2016-07"

  strings:
            $a0 = { 38 02 ?? ?? ?? 26 16 }
    $a1 = "System.Void System.Array::Reverse(System.Array)" fullword wide ascii nocase
    $a2 = "System.Security.Cryptography.SymmetricAlgorithm" fullword wide ascii nocase
    $a3 = "System.Security.Cryptography.AesCryptoServiceProvider" fullword wide ascii nocase

    $b0 = "System.Diagnostics.Process" fullword wide ascii nocase
    $b1 = "System.Diagnostics.StackFrame" fullword wide ascii nocase

    $c0 = "Rijndael" fullword wide ascii nocase
    $c1 = "System.Security.Cryptography" fullword wide ascii nocase
    $c2 = "ICryptoTransform" fullword wide ascii nocase

  condition:
    (pe.imports("mscoree.dll", "_CorExeMain") or pe.imports("mscoree.dll", "_CorDllMain"))
    and
    (
      3 of ($c*)
      or
      2 of ($b*)
      or
      1 of ($a*)
    )
}