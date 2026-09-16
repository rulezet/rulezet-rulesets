rule TTP_XOR_QUAD_CurrentVersionRun_694d {
  strings:
    $key_694d = { 3a 22 [2] 1e 2c [2] 35 00 [2] 1b 22 [2] 0f 39 [2] 00 23 [2] 1e 3e [2] 1c 3f [2] 07 39 [2] 1b 3e [2] 07 11 }

  condition:
    any of them
}