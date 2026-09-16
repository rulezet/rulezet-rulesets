rule TTP_XOR_QUAD_CurrentVersionRun_b8ee {
  strings:
    $key_b8ee = { eb 81 [2] cf 8f [2] e4 a3 [2] ca 81 [2] de 9a [2] d1 80 [2] cf 9d [2] cd 9c [2] d6 9a [2] ca 9d [2] d6 b2 }

  condition:
    any of them
}