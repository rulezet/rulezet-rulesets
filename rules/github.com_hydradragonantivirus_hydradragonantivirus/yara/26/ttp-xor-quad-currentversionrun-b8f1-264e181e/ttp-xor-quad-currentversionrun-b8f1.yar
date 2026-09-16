rule TTP_XOR_QUAD_CurrentVersionRun_b8f1 {
  strings:
    $key_b8f1 = { eb 9e [2] cf 90 [2] e4 bc [2] ca 9e [2] de 85 [2] d1 9f [2] cf 82 [2] cd 83 [2] d6 85 [2] ca 82 [2] d6 ad }

  condition:
    any of them
}