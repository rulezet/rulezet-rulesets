rule TTP_XOR_QUAD_CurrentVersionRun_e8fd {
  strings:
    $key_e8fd = { bb 92 [2] 9f 9c [2] b4 b0 [2] 9a 92 [2] 8e 89 [2] 81 93 [2] 9f 8e [2] 9d 8f [2] 86 89 [2] 9a 8e [2] 86 a1 }

  condition:
    any of them
}