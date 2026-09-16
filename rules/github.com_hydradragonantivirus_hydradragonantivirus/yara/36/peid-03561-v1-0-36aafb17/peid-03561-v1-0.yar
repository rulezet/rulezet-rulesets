rule PEiD_03561____________v1_0_________ {
  meta:
    description = "[convert base64 to ascii w47DhMK8w77DgMKmwrDDs8OGw7cgdjEuMCAtPiDDkMOtw5TDhg==]"
    ep_only     = "true"

  strings:
    $a = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 1C 30 40 00 }

  condition:
    $a
}