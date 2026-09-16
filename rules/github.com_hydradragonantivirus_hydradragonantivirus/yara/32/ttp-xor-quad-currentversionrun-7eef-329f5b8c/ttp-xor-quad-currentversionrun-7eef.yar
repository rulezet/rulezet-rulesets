rule TTP_XOR_QUAD_CurrentVersionRun_7eef {
  strings:
    $key_7eef = { 2d 80 [2] 09 8e [2] 22 a2 [2] 0c 80 [2] 18 9b [2] 17 81 [2] 09 9c [2] 0b 9d [2] 10 9b [2] 0c 9c [2] 10 b3 }

  condition:
    any of them
}