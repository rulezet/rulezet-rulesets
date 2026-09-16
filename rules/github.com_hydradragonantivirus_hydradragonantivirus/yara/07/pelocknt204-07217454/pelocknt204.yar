import "pe"
rule pelocknt204 {
  meta:
    author      = "PEiD"
    description = "PE Lock NT 2.04 -> :MARQUiS:"
    group       = "148"
    function    = "0"

  strings:
    $a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB }

  condition:
    $a0 at pe.entry_point
}