rule TTP_XOR_QUAD_CurrentVersionRun_5633 {
  strings:
    $key_5633 = { 05 5c [2] 21 52 [2] 0a 7e [2] 24 5c [2] 30 47 [2] 3f 5d [2] 21 40 [2] 23 41 [2] 38 47 [2] 24 40 [2] 38 6f }

  condition:
    any of them
}