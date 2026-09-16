rule TTP_XOR_QUAD_CurrentVersionRun_b86d {
  strings:
    $key_b86d = { eb 02 [2] cf 0c [2] e4 20 [2] ca 02 [2] de 19 [2] d1 03 [2] cf 1e [2] cd 1f [2] d6 19 [2] ca 1e [2] d6 31 }

  condition:
    any of them
}