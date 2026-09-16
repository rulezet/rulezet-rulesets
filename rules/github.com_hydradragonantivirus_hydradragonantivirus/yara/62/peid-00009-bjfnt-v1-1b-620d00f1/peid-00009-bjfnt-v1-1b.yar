rule PEiD_00009__BJFnt_v1_1b_ {
  meta:
    description = "[.BJFnt v1.1b]"
    ep_only     = "true"

  strings:
    $a = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }

  condition:
    $a
}