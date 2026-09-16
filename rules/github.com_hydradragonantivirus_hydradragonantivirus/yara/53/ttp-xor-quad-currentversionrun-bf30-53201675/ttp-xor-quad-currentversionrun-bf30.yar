rule TTP_XOR_QUAD_CurrentVersionRun_bf30 {
  strings:
    $key_bf30 = { ec 5f [2] c8 51 [2] e3 7d [2] cd 5f [2] d9 44 [2] d6 5e [2] c8 43 [2] ca 42 [2] d1 44 [2] cd 43 [2] d1 6c }

  condition:
    any of them
}