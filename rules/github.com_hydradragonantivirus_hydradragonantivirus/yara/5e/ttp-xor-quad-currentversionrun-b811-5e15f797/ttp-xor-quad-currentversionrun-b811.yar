rule TTP_XOR_QUAD_CurrentVersionRun_b811 {
  strings:
    $key_b811 = { eb 7e [2] cf 70 [2] e4 5c [2] ca 7e [2] de 65 [2] d1 7f [2] cf 62 [2] cd 63 [2] d6 65 [2] ca 62 [2] d6 4d }

  condition:
    any of them
}