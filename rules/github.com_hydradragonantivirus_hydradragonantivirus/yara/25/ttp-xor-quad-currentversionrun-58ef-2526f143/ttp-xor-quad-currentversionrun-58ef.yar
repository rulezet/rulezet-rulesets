rule TTP_XOR_QUAD_CurrentVersionRun_58ef {
  strings:
    $key_58ef = { 0b 80 [2] 2f 8e [2] 04 a2 [2] 2a 80 [2] 3e 9b [2] 31 81 [2] 2f 9c [2] 2d 9d [2] 36 9b [2] 2a 9c [2] 36 b3 }

  condition:
    any of them
}