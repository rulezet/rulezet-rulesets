rule TTP_XOR_QUAD_CurrentVersionRun_bff3 {
  strings:
    $key_bff3 = { ec 9c [2] c8 92 [2] e3 be [2] cd 9c [2] d9 87 [2] d6 9d [2] c8 80 [2] ca 81 [2] d1 87 [2] cd 80 [2] d1 af }

  condition:
    any of them
}