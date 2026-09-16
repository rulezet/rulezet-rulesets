rule TTP_XOR_QUAD_CurrentVersionRun_b80f {
  strings:
    $key_b80f = { eb 60 [2] cf 6e [2] e4 42 [2] ca 60 [2] de 7b [2] d1 61 [2] cf 7c [2] cd 7d [2] d6 7b [2] ca 7c [2] d6 53 }

  condition:
    any of them
}