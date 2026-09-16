rule TTP_XOR_QUAD_CurrentVersionRun_b87f {
  strings:
    $key_b87f = { eb 10 [2] cf 1e [2] e4 32 [2] ca 10 [2] de 0b [2] d1 11 [2] cf 0c [2] cd 0d [2] d6 0b [2] ca 0c [2] d6 23 }

  condition:
    any of them
}