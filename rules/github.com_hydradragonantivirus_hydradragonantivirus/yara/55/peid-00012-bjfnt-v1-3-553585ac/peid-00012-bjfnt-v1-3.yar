rule PEiD_00012__BJFnt_v1_3_ {
  meta:
    description = "[.BJFnt v1.3]"
    ep_only     = "true"

  strings:
    $a = { EB ?? 3A ?? ?? 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB }

  condition:
    $a
}