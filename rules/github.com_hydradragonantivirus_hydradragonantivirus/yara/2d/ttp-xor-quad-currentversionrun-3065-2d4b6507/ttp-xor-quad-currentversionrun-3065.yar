rule TTP_XOR_QUAD_CurrentVersionRun_3065 {
  strings:
    $key_3065 = { 63 0a [2] 47 04 [2] 6c 28 [2] 42 0a [2] 56 11 [2] 59 0b [2] 47 16 [2] 45 17 [2] 5e 11 [2] 42 16 [2] 5e 39 }

  condition:
    any of them
}