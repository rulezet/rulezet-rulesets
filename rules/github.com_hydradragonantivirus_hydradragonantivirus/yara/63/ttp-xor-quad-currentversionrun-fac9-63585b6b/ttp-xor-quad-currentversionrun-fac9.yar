rule TTP_XOR_QUAD_CurrentVersionRun_fac9 {
  strings:
    $key_fac9 = { a9 a6 [2] 8d a8 [2] a6 84 [2] 88 a6 [2] 9c bd [2] 93 a7 [2] 8d ba [2] 8f bb [2] 94 bd [2] 88 ba [2] 94 95 }

  condition:
    any of them
}