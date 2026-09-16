rule TTP_XOR_QUAD_CurrentVersionRun_b82d {
  strings:
    $key_b82d = { eb 42 [2] cf 4c [2] e4 60 [2] ca 42 [2] de 59 [2] d1 43 [2] cf 5e [2] cd 5f [2] d6 59 [2] ca 5e [2] d6 71 }

  condition:
    any of them
}