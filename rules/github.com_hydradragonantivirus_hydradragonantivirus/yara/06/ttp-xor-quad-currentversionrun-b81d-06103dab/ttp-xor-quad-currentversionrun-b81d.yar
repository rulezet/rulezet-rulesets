rule TTP_XOR_QUAD_CurrentVersionRun_b81d {
  strings:
    $key_b81d = { eb 72 [2] cf 7c [2] e4 50 [2] ca 72 [2] de 69 [2] d1 73 [2] cf 6e [2] cd 6f [2] d6 69 [2] ca 6e [2] d6 41 }

  condition:
    any of them
}