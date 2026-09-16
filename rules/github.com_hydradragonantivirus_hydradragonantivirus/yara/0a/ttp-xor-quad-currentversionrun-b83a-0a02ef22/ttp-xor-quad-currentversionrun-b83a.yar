rule TTP_XOR_QUAD_CurrentVersionRun_b83a {
  strings:
    $key_b83a = { eb 55 [2] cf 5b [2] e4 77 [2] ca 55 [2] de 4e [2] d1 54 [2] cf 49 [2] cd 48 [2] d6 4e [2] ca 49 [2] d6 66 }

  condition:
    any of them
}