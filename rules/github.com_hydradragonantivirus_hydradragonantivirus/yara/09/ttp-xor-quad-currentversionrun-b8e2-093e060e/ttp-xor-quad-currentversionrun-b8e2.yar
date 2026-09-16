rule TTP_XOR_QUAD_CurrentVersionRun_b8e2 {
  strings:
    $key_b8e2 = { eb 8d [2] cf 83 [2] e4 af [2] ca 8d [2] de 96 [2] d1 8c [2] cf 91 [2] cd 90 [2] d6 96 [2] ca 91 [2] d6 be }

  condition:
    any of them
}