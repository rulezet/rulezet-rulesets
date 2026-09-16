rule TTP_XOR_QUAD_CurrentVersionRun_3068 {
  strings:
    $key_3068 = { 63 07 [2] 47 09 [2] 6c 25 [2] 42 07 [2] 56 1c [2] 59 06 [2] 47 1b [2] 45 1a [2] 5e 1c [2] 42 1b [2] 5e 34 }

  condition:
    any of them
}