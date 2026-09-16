rule TTP_XOR_QUAD_CurrentVersionRun_2d33 {
  strings:
    $key_2d33 = { 7e 5c [2] 5a 52 [2] 71 7e [2] 5f 5c [2] 4b 47 [2] 44 5d [2] 5a 40 [2] 58 41 [2] 43 47 [2] 5f 40 [2] 43 6f }

  condition:
    any of them
}