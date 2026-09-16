rule TTP_XOR_QUAD_CurrentVersionRun_1f33 {
  strings:
    $key_1f33 = { 4c 5c [2] 68 52 [2] 43 7e [2] 6d 5c [2] 79 47 [2] 76 5d [2] 68 40 [2] 6a 41 [2] 71 47 [2] 6d 40 [2] 71 6f }

  condition:
    any of them
}