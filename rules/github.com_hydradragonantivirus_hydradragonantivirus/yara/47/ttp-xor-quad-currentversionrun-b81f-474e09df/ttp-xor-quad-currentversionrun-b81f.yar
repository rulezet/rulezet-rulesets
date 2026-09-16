rule TTP_XOR_QUAD_CurrentVersionRun_b81f {
  strings:
    $key_b81f = { eb 70 [2] cf 7e [2] e4 52 [2] ca 70 [2] de 6b [2] d1 71 [2] cf 6c [2] cd 6d [2] d6 6b [2] ca 6c [2] d6 43 }

  condition:
    any of them
}