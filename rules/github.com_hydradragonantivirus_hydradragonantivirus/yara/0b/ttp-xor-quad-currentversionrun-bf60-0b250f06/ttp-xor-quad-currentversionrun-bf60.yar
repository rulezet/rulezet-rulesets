rule TTP_XOR_QUAD_CurrentVersionRun_bf60 {
  strings:
    $key_bf60 = { ec 0f [2] c8 01 [2] e3 2d [2] cd 0f [2] d9 14 [2] d6 0e [2] c8 13 [2] ca 12 [2] d1 14 [2] cd 13 [2] d1 3c }

  condition:
    any of them
}