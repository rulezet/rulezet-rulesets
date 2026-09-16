rule TTP_XOR_QUAD_CurrentVersionRun_b812 {
  strings:
    $key_b812 = { eb 7d [2] cf 73 [2] e4 5f [2] ca 7d [2] de 66 [2] d1 7c [2] cf 61 [2] cd 60 [2] d6 66 [2] ca 61 [2] d6 4e }

  condition:
    any of them
}