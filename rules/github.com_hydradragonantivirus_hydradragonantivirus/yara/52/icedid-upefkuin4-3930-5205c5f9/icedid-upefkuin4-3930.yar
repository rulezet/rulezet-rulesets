import "pe"
rule icedid_upefkuin4_3930 {
  meta:
    description = "3930 - file upefkuin4.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-06-09"
    hash1       = "666570229dd5af87fede86b9191fb1e8352d276a8a32c42e4bf4128a4f7e8138"

  strings:
    $s1  = "UAWAVAUATVWSH" fullword ascii
    $s2  = "AWAVAUATVWUSH" fullword ascii
    $s3  = "AWAVATVWUSH" fullword ascii
    $s4  = "update" fullword ascii  
    $s5  = "?ortpw@@YAHXZ" fullword ascii
    $s6  = "?sortyW@@YAHXZ" fullword ascii
    $s7  = "?sorty@@YAHXZ" fullword ascii
    $s8  = "?keptyu@@YAHXZ" fullword ascii
    $s9  = "*=UUUUr#L" fullword ascii
    $s10 = "*=UUUUr!" fullword ascii
    $s11 = "PluginInit" fullword ascii
    $s12 = "*=UUUUr\"" fullword ascii
    $s13 = "AVVWSH" fullword ascii
    $s14 = "D$4iL$ " fullword ascii
    $s15 = "X[]_^A\\A]A^A_" fullword ascii
    $s16 = "D$4iT$ " fullword ascii
    $s17 = "H[]_^A\\A]A^A_" fullword ascii
    $s18 = "L94iL$ " fullword ascii
    $s19 = "D$ iD$ " fullword ascii
    $s20 = "*=UUUUr " fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and
    (pe.imphash() == "87bed5a7cba00c7e1f4015f1bdae2183" and (pe.exports("?keptyu@@YAHXZ") and pe.exports("?ortpw@@YAHXZ") and pe.exports("?sorty@@YAHXZ") and pe.exports("?sortyW@@YAHXZ") and pe.exports("PluginInit") and pe.exports("update")) or 8 of them)
}