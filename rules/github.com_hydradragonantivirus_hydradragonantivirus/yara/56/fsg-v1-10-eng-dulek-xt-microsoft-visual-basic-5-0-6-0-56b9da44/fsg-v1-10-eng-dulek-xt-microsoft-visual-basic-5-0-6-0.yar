import "pe"
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_Basic_5_0___6_0_ {
  strings:
    $a0 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }

  condition:
    $a0 at pe.entry_point
}