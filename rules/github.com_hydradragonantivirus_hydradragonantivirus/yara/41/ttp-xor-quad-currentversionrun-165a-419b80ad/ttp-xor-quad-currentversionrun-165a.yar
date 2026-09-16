rule TTP_XOR_QUAD_CurrentVersionRun_165a {
  strings:
    $key_165a = { 45 35 [2] 61 3b [2] 4a 17 [2] 64 35 [2] 70 2e [2] 7f 34 [2] 61 29 [2] 63 28 [2] 78 2e [2] 64 29 [2] 78 06 }

  condition:
    any of them
}