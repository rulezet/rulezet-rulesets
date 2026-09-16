rule TTP_XOR_QUAD_CurrentVersionRun_0eef {
  strings:
    $key_0eef = { 5d 80 [2] 79 8e [2] 52 a2 [2] 7c 80 [2] 68 9b [2] 67 81 [2] 79 9c [2] 7b 9d [2] 60 9b [2] 7c 9c [2] 60 b3 }

  condition:
    any of them
}