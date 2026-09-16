rule PEiD_01860_PseudoSigner_0_2__Borland_C___DLL__Method_2___ {
  meta:
    description = "[PseudoSigner 0.2 [Borland C++ DLL (Method 2)]]"
    ep_only     = "true"

  strings:
    $a = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }

  condition:
    $a
}