rule TTP_XOR_QUAD_CurrentVersionRun_b821 {
  strings:
    $key_b821 = { eb 4e [2] cf 40 [2] e4 6c [2] ca 4e [2] de 55 [2] d1 4f [2] cf 52 [2] cd 53 [2] d6 55 [2] ca 52 [2] d6 7d }

  condition:
    any of them
}