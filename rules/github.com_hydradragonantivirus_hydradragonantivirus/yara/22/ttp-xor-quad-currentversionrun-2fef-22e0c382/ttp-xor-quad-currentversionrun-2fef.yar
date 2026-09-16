rule TTP_XOR_QUAD_CurrentVersionRun_2fef {
  strings:
    $key_2fef = { 7c 80 [2] 58 8e [2] 73 a2 [2] 5d 80 [2] 49 9b [2] 46 81 [2] 58 9c [2] 5a 9d [2] 41 9b [2] 5d 9c [2] 41 b3 }

  condition:
    any of them
}