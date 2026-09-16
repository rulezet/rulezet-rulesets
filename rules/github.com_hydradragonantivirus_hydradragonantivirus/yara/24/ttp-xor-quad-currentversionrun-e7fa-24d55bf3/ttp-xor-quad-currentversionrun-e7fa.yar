rule TTP_XOR_QUAD_CurrentVersionRun_e7fa {
  strings:
    $key_e7fa = { b4 95 [2] 90 9b [2] bb b7 [2] 95 95 [2] 81 8e [2] 8e 94 [2] 90 89 [2] 92 88 [2] 89 8e [2] 95 89 [2] 89 a6 }

  condition:
    any of them
}