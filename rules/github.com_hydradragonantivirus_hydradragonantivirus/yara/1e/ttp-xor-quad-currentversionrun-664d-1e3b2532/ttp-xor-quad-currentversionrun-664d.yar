rule TTP_XOR_QUAD_CurrentVersionRun_664d {
  strings:
    $key_664d = { 35 22 [2] 11 2c [2] 3a 00 [2] 14 22 [2] 00 39 [2] 0f 23 [2] 11 3e [2] 13 3f [2] 08 39 [2] 14 3e [2] 08 11 }

  condition:
    any of them
}