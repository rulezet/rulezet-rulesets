rule TTP_XOR_QUAD_CurrentVersionRun_e37d {
  strings:
    $key_e37d = { b0 12 [2] 94 1c [2] bf 30 [2] 91 12 [2] 85 09 [2] 8a 13 [2] 94 0e [2] 96 0f [2] 8d 09 [2] 91 0e [2] 8d 21 }

  condition:
    any of them
}