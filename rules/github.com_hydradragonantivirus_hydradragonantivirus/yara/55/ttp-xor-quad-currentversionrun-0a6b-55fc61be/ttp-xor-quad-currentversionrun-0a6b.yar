rule TTP_XOR_QUAD_CurrentVersionRun_0a6b {
  strings:
    $key_0a6b = { 59 04 [2] 7d 0a [2] 56 26 [2] 78 04 [2] 6c 1f [2] 63 05 [2] 7d 18 [2] 7f 19 [2] 64 1f [2] 78 18 [2] 64 37 }

  condition:
    any of them
}