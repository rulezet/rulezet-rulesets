rule TTP_XOR_QUAD_CurrentVersionRun_2333 {
  strings:
    $key_2333 = { 70 5c [2] 54 52 [2] 7f 7e [2] 51 5c [2] 45 47 [2] 4a 5d [2] 54 40 [2] 56 41 [2] 4d 47 [2] 51 40 [2] 4d 6f }

  condition:
    any of them
}