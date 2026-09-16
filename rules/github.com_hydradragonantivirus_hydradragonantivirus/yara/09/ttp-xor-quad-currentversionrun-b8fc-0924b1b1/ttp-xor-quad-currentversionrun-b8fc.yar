rule TTP_XOR_QUAD_CurrentVersionRun_b8fc {
  strings:
    $key_b8fc = { eb 93 [2] cf 9d [2] e4 b1 [2] ca 93 [2] de 88 [2] d1 92 [2] cf 8f [2] cd 8e [2] d6 88 [2] ca 8f [2] d6 a0 }

  condition:
    any of them
}