rule TTP_XOR_QUAD_CurrentVersionRun_31fd {
  strings:
    $key_31fd = { 62 92 [2] 46 9c [2] 6d b0 [2] 43 92 [2] 57 89 [2] 58 93 [2] 46 8e [2] 44 8f [2] 5f 89 [2] 43 8e [2] 5f a1 }

  condition:
    any of them
}