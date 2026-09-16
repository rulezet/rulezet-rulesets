rule TTP_XOR_QUAD_CurrentVersionRun_b8e0 {
  strings:
    $key_b8e0 = { eb 8f [2] cf 81 [2] e4 ad [2] ca 8f [2] de 94 [2] d1 8e [2] cf 93 [2] cd 92 [2] d6 94 [2] ca 93 [2] d6 bc }

  condition:
    any of them
}