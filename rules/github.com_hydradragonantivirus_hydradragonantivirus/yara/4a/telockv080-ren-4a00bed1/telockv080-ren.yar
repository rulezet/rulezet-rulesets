import "pe"
rule tElockv080_ren: tE {
  meta:
    author = "_pusher_"
    date   = "2015-11"

  strings:
    $a0 = { 60 E8 F9 11 ?? ?? C3 83 }

  condition:
    $a0 at pe.entry_point
}