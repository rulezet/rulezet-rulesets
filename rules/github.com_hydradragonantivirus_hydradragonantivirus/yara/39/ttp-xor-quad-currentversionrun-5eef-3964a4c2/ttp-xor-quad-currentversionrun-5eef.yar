rule TTP_XOR_QUAD_CurrentVersionRun_5eef {
  strings:
    $key_5eef = { 0d 80 [2] 29 8e [2] 02 a2 [2] 2c 80 [2] 38 9b [2] 37 81 [2] 29 9c [2] 2b 9d [2] 30 9b [2] 2c 9c [2] 30 b3 }

  condition:
    any of them
}