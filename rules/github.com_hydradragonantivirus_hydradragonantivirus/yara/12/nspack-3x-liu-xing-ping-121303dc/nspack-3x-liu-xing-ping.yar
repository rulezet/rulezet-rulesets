import "pe"
rule _NsPack_3x__Liu_Xing_Ping_ {
  meta:
    description = "NsPack 3.x -> Liu Xing Ping"

  strings:
    $0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D }

  condition:
    $0 at pe.entry_point
}