rule TTP_XOR_QUAD_CurrentVersionRun_0a4b {
  strings:
    $key_0a4b = { 59 24 [2] 7d 2a [2] 56 06 [2] 78 24 [2] 6c 3f [2] 63 25 [2] 7d 38 [2] 7f 39 [2] 64 3f [2] 78 38 [2] 64 17 }

  condition:
    any of them
}