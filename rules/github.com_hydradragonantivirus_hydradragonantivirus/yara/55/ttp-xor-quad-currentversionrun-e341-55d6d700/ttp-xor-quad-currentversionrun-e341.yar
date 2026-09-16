rule TTP_XOR_QUAD_CurrentVersionRun_e341 {
  strings:
    $key_e341 = { b0 2e [2] 94 20 [2] bf 0c [2] 91 2e [2] 85 35 [2] 8a 2f [2] 94 32 [2] 96 33 [2] 8d 35 [2] 91 32 [2] 8d 1d }

  condition:
    any of them
}