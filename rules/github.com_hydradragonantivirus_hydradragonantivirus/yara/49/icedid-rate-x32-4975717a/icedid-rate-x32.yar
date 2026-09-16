import "pe"
rule icedid_rate_x32 {
  meta:
    description = "files - file rate_x32.dat"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-05-09"
    hash1       = "eb79168391e64160883b1b3839ed4045b4fd40da14d6eec5a93cfa9365503586"

  strings:
    $s1  = "UAWAVAUATVWSH" fullword ascii
    $s2  = "UAWAVVWSPH" fullword ascii
    $s3  = "AWAVAUATVWUSH" fullword ascii
    $s4  = "update" fullword ascii  
    $s5  = "?klopW@@YAHXZ" fullword ascii
    $s6  = "?jutre@@YAHXZ" fullword ascii
    $s7  = "PluginInit" fullword ascii
    $s8  = "[]_^A\\A]A^A_" fullword ascii
    $s9  = "e8[_^A\\A]A^A_]" fullword ascii
    $s10 = "[_^A\\A]A^A_]" fullword ascii
    $s11 = "Kts=R,4iu" fullword ascii
    $s12 = "mqr55c" fullword ascii
    $s13 = "R,4i=Bj" fullword ascii
    $s14 = "Ktw=R,4iu" fullword ascii
    $s15 = "Ktu=R,4iu" fullword ascii
    $s16 = "Kt{=R,4iu" fullword ascii
    $s17 = "KVL.Mp" fullword ascii
    $s18 = "Kt|=R,4iu" fullword ascii
    $s19 = "=8c[Vt8=" fullword ascii
    $s20 = "Ktx=R,4iu" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and
    (pe.imphash() == "15787e97e92f1f138de37f6f972eb43c" and (pe.exports("?jutre@@YAHXZ") and pe.exports("?klopW@@YAHXZ") and pe.exports("PluginInit") and pe.exports("update")) or 8 of them)
}