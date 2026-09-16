rule TTP_XOR_QUAD_CurrentVersionRun_0a77 {
  strings:
    $key_0a77 = { 59 18 [2] 7d 16 [2] 56 3a [2] 78 18 [2] 6c 03 [2] 63 19 [2] 7d 04 [2] 7f 05 [2] 64 03 [2] 78 04 [2] 64 2b }

  condition:
    any of them
}