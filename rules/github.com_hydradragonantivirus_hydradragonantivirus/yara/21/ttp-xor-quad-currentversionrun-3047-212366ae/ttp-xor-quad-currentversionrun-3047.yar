rule TTP_XOR_QUAD_CurrentVersionRun_3047 {
  strings:
    $key_3047 = { 63 28 [2] 47 26 [2] 6c 0a [2] 42 28 [2] 56 33 [2] 59 29 [2] 47 34 [2] 45 35 [2] 5e 33 [2] 42 34 [2] 5e 1b }

  condition:
    any of them
}