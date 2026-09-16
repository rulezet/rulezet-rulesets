rule TTP_XOR_QUAD_CurrentVersionRun_f20d {
  strings:
    $key_f20d = { a1 62 [2] 85 6c [2] ae 40 [2] 80 62 [2] 94 79 [2] 9b 63 [2] 85 7e [2] 87 7f [2] 9c 79 [2] 80 7e [2] 9c 51 }

  condition:
    any of them
}