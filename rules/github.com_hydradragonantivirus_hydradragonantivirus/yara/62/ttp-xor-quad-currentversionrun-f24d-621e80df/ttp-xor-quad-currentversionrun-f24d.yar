rule TTP_XOR_QUAD_CurrentVersionRun_f24d {
  strings:
    $key_f24d = { a1 22 [2] 85 2c [2] ae 00 [2] 80 22 [2] 94 39 [2] 9b 23 [2] 85 3e [2] 87 3f [2] 9c 39 [2] 80 3e [2] 9c 11 }

  condition:
    any of them
}