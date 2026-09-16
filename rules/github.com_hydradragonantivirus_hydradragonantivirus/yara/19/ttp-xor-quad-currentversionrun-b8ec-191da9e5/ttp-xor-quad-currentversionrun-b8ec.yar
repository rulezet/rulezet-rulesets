rule TTP_XOR_QUAD_CurrentVersionRun_b8ec {
  strings:
    $key_b8ec = { eb 83 [2] cf 8d [2] e4 a1 [2] ca 83 [2] de 98 [2] d1 82 [2] cf 9f [2] cd 9e [2] d6 98 [2] ca 9f [2] d6 b0 }

  condition:
    any of them
}