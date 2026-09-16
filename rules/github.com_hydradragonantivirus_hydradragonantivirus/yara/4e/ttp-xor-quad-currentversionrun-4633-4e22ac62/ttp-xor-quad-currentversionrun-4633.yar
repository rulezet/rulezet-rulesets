rule TTP_XOR_QUAD_CurrentVersionRun_4633 {
  strings:
    $key_4633 = { 15 5c [2] 31 52 [2] 1a 7e [2] 34 5c [2] 20 47 [2] 2f 5d [2] 31 40 [2] 33 41 [2] 28 47 [2] 34 40 [2] 28 6f }

  condition:
    any of them
}