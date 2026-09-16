rule TTP_XOR_QUAD_CurrentVersionRun_b810 {
  strings:
    $key_b810 = { eb 7f [2] cf 71 [2] e4 5d [2] ca 7f [2] de 64 [2] d1 7e [2] cf 63 [2] cd 62 [2] d6 64 [2] ca 63 [2] d6 4c }

  condition:
    any of them
}