import "pe"
rule tElockv071b7_ren: tE {
  meta:
    author = "_pusher_"
    date   = "2015-11"

  strings:
    $a0 = { 60 E8 48 11 ?? ?? C3 83 }

  condition:
    $a0 at pe.entry_point
}