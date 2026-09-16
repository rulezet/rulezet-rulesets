rule TTP_XOR_QUAD_CurrentVersionRun_b8e9 {
  strings:
    $key_b8e9 = { eb 86 [2] cf 88 [2] e4 a4 [2] ca 86 [2] de 9d [2] d1 87 [2] cf 9a [2] cd 9b [2] d6 9d [2] ca 9a [2] d6 b5 }

  condition:
    any of them
}