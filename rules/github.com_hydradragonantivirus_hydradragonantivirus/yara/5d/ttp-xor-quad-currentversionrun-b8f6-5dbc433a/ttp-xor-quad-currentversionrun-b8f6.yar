rule TTP_XOR_QUAD_CurrentVersionRun_b8f6 {
  strings:
    $key_b8f6 = { eb 99 [2] cf 97 [2] e4 bb [2] ca 99 [2] de 82 [2] d1 98 [2] cf 85 [2] cd 84 [2] d6 82 [2] ca 85 [2] d6 aa }

  condition:
    any of them
}