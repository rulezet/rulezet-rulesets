rule TTP_XOR_QUAD_CurrentVersionRun_3eef {
  strings:
    $key_3eef = { 6d 80 [2] 49 8e [2] 62 a2 [2] 4c 80 [2] 58 9b [2] 57 81 [2] 49 9c [2] 4b 9d [2] 50 9b [2] 4c 9c [2] 50 b3 }

  condition:
    any of them
}