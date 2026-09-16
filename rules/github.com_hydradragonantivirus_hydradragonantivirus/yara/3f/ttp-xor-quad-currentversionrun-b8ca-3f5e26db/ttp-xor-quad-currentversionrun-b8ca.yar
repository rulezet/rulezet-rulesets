rule TTP_XOR_QUAD_CurrentVersionRun_b8ca {
  strings:
    $key_b8ca = { eb a5 [2] cf ab [2] e4 87 [2] ca a5 [2] de be [2] d1 a4 [2] cf b9 [2] cd b8 [2] d6 be [2] ca b9 [2] d6 96 }

  condition:
    any of them
}