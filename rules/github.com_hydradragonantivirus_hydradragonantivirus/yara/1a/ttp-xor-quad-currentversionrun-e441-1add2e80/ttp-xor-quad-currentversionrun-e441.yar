rule TTP_XOR_QUAD_CurrentVersionRun_e441 {
  strings:
    $key_e441 = { b7 2e [2] 93 20 [2] b8 0c [2] 96 2e [2] 82 35 [2] 8d 2f [2] 93 32 [2] 91 33 [2] 8a 35 [2] 96 32 [2] 8a 1d }

  condition:
    any of them
}