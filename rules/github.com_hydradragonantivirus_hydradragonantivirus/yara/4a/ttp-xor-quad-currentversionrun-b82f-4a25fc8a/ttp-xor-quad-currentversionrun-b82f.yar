rule TTP_XOR_QUAD_CurrentVersionRun_b82f {
  strings:
    $key_b82f = { eb 40 [2] cf 4e [2] e4 62 [2] ca 40 [2] de 5b [2] d1 41 [2] cf 5c [2] cd 5d [2] d6 5b [2] ca 5c [2] d6 73 }

  condition:
    any of them
}