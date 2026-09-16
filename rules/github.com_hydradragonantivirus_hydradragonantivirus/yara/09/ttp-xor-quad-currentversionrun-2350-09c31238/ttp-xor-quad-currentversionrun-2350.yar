rule TTP_XOR_QUAD_CurrentVersionRun_2350 {
  strings:
    $key_2350 = { 70 3f [2] 54 31 [2] 7f 1d [2] 51 3f [2] 45 24 [2] 4a 3e [2] 54 23 [2] 56 22 [2] 4d 24 [2] 51 23 [2] 4d 0c }

  condition:
    any of them
}