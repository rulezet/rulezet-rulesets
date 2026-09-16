rule TTP_XOR_QUAD_CurrentVersionRun_3077 {
  strings:
    $key_3077 = { 63 18 [2] 47 16 [2] 6c 3a [2] 42 18 [2] 56 03 [2] 59 19 [2] 47 04 [2] 45 05 [2] 5e 03 [2] 42 04 [2] 5e 2b }

  condition:
    any of them
}