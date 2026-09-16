rule TTP_XOR_QUAD_CurrentVersionRun_b814 {
  strings:
    $key_b814 = { eb 7b [2] cf 75 [2] e4 59 [2] ca 7b [2] de 60 [2] d1 7a [2] cf 67 [2] cd 66 [2] d6 60 [2] ca 67 [2] d6 48 }

  condition:
    any of them
}