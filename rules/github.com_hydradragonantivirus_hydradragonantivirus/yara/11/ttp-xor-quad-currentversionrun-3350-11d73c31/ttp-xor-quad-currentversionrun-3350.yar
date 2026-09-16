rule TTP_XOR_QUAD_CurrentVersionRun_3350 {
  strings:
    $key_3350 = { 60 3f [2] 44 31 [2] 6f 1d [2] 41 3f [2] 55 24 [2] 5a 3e [2] 44 23 [2] 46 22 [2] 5d 24 [2] 41 23 [2] 5d 0c }

  condition:
    any of them
}