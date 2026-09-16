rule TTP_XOR_QUAD_CurrentVersionRun_e3f0 {
  strings:
    $key_e3f0 = { b0 9f [2] 94 91 [2] bf bd [2] 91 9f [2] 85 84 [2] 8a 9e [2] 94 83 [2] 96 82 [2] 8d 84 [2] 91 83 [2] 8d ac }

  condition:
    any of them
}