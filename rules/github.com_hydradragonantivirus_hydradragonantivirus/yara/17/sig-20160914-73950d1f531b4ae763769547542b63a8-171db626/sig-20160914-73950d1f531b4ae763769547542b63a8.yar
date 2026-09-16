rule sig_20160914_73950d1f531b4ae763769547542b63a8 {
  meta:
    description = "datamaliciousorder - file 20160914_73950d1f531b4ae763769547542b63a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebb7c03efe294e5e78794d43b0d851e0eb2031eebfda4edbaf124341f6afc6e4"

  strings:
    $s1  = "function f52f1()" fullword ascii
    $s2  = "function e6cc2(d75d9)" fullword ascii
    $s3  = "function c1fd0()" fullword ascii
    $s4  = "return new Array('c5894','e(parseIn','d9da1')[Math.floor(Math.random()*3)];" fullword ascii
    $s5  = "function bbf90()" fullword ascii
    $s6  = "return(new Function(e46c0)());" fullword ascii
    $s7  = "return new Array('c5894','16','d9da1','d9da1','d9da1')[Math.floor(Math.random()*5)];" fullword ascii
    $s8  = "return ccd42;" fullword ascii
    $s9  = "return new Array('c5894','r','d9da1')[Math.floor(Math.random()*3)];" fullword ascii
    $s10 = "while(bf959<1)" fullword ascii
    $s11 = "function fdba1(e46c0)" fullword ascii
    $s12 = "return (new Function('ba1a7',''+f52f1()+''+'eturn'+''+' String.fromCharCod'+c1fd0()+'t(ba1a7,'+bbf90()+')^7)')(fa0d4));" fullword ascii
    $s13 = "function d158e(fa0d4)" fullword ascii
    $s14 = "while(d9205<adc46.length)" fullword ascii
    $s15 = "catch(a156e)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}