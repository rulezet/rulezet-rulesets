rule TTP_XOR_QUAD_CurrentVersionRun_b802 {
  strings:
    $key_b802 = { eb 6d [2] cf 63 [2] e4 4f [2] ca 6d [2] de 76 [2] d1 6c [2] cf 71 [2] cd 70 [2] d6 76 [2] ca 71 [2] d6 5e }

  condition:
    any of them
}