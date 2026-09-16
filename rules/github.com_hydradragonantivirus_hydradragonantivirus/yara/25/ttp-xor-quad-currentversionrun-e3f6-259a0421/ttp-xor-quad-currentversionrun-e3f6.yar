rule TTP_XOR_QUAD_CurrentVersionRun_e3f6 {
  strings:
    $key_e3f6 = { b0 99 [2] 94 97 [2] bf bb [2] 91 99 [2] 85 82 [2] 8a 98 [2] 94 85 [2] 96 84 [2] 8d 82 [2] 91 85 [2] 8d aa }

  condition:
    any of them
}