rule TTP_XOR_QUAD_CurrentVersionRun_bfd4 {
  strings:
    $key_bfd4 = { ec bb [2] c8 b5 [2] e3 99 [2] cd bb [2] d9 a0 [2] d6 ba [2] c8 a7 [2] ca a6 [2] d1 a0 [2] cd a7 [2] d1 88 }

  condition:
    any of them
}