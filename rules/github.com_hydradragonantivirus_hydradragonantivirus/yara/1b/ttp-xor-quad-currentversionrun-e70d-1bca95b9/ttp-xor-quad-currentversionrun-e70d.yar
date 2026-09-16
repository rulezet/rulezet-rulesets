rule TTP_XOR_QUAD_CurrentVersionRun_e70d {
  strings:
    $key_e70d = { b4 62 [2] 90 6c [2] bb 40 [2] 95 62 [2] 81 79 [2] 8e 63 [2] 90 7e [2] 92 7f [2] 89 79 [2] 95 7e [2] 89 51 }

  condition:
    any of them
}