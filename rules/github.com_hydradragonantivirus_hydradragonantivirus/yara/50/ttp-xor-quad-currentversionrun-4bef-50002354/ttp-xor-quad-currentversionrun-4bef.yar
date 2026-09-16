rule TTP_XOR_QUAD_CurrentVersionRun_4bef {
  strings:
    $key_4bef = { 18 80 [2] 3c 8e [2] 17 a2 [2] 39 80 [2] 2d 9b [2] 22 81 [2] 3c 9c [2] 3e 9d [2] 25 9b [2] 39 9c [2] 25 b3 }

  condition:
    any of them
}