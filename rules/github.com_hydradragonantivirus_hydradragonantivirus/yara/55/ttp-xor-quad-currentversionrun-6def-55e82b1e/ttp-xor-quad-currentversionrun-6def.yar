rule TTP_XOR_QUAD_CurrentVersionRun_6def {
  strings:
    $key_6def = { 3e 80 [2] 1a 8e [2] 31 a2 [2] 1f 80 [2] 0b 9b [2] 04 81 [2] 1a 9c [2] 18 9d [2] 03 9b [2] 1f 9c [2] 03 b3 }

  condition:
    any of them
}