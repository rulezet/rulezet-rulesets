rule TTP_XOR_QUAD_CurrentVersionRun_b822 {
  strings:
    $key_b822 = { eb 4d [2] cf 43 [2] e4 6f [2] ca 4d [2] de 56 [2] d1 4c [2] cf 51 [2] cd 50 [2] d6 56 [2] ca 51 [2] d6 7e }

  condition:
    any of them
}