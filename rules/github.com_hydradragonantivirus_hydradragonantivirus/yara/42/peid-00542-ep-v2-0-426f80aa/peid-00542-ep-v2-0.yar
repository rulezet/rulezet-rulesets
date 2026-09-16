rule PEiD_00542_EP_v2_0_ {
  meta:
    description = "[EP v2.0]"
    ep_only     = "true"

  strings:
    $a = { 6A ?? 60 E9 01 01 }

  condition:
    $a
}