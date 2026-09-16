rule TTP_XOR_QUAD_CurrentVersionRun_7fef {
  strings:
    $key_7fef = { 2c 80 [2] 08 8e [2] 23 a2 [2] 0d 80 [2] 19 9b [2] 16 81 [2] 08 9c [2] 0a 9d [2] 11 9b [2] 0d 9c [2] 11 b3 }

  condition:
    any of them
}