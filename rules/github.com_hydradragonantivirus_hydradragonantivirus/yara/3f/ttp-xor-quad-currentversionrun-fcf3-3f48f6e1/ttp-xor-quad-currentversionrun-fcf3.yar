rule TTP_XOR_QUAD_CurrentVersionRun_fcf3 {
  strings:
    $key_fcf3 = { af 9c [2] 8b 92 [2] a0 be [2] 8e 9c [2] 9a 87 [2] 95 9d [2] 8b 80 [2] 89 81 [2] 92 87 [2] 8e 80 [2] 92 af }

  condition:
    any of them
}