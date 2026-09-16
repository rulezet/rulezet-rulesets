import "pe"
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___5_0___6_0_ {
  strings:
    $a0 = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }

  condition:
    $a0 at pe.entry_point
}