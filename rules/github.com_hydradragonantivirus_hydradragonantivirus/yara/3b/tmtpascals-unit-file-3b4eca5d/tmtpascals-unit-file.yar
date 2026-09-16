import "pe"
rule _TMTPascals_Unit_file_ {
  meta:
    description = "TMT-Pascal's Unit file"

  strings:
    $0 = { 50 00 00 00 53 50 46 50 }

  condition:
    $0 at pe.entry_point
}