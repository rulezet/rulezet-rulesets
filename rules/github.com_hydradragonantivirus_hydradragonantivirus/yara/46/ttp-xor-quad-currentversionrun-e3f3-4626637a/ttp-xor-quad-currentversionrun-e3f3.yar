rule TTP_XOR_QUAD_CurrentVersionRun_e3f3 {
  strings:
    $key_e3f3 = { b0 9c [2] 94 92 [2] bf be [2] 91 9c [2] 85 87 [2] 8a 9d [2] 94 80 [2] 96 81 [2] 8d 87 [2] 91 80 [2] 8d af }

  condition:
    any of them
}