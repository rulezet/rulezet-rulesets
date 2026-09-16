rule TTP_XOR_QUAD_CurrentVersionRun_4763 {
  strings:
    $key_4763 = { 14 0c [2] 30 02 [2] 1b 2e [2] 35 0c [2] 21 17 [2] 2e 0d [2] 30 10 [2] 32 11 [2] 29 17 [2] 35 10 [2] 29 3f }

  condition:
    any of them
}