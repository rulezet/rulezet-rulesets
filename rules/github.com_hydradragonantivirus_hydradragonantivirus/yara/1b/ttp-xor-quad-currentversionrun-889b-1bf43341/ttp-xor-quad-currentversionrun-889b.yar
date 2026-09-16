rule TTP_XOR_QUAD_CurrentVersionRun_889b {
  strings:
    $key_889b = { db f4 [2] ff fa [2] d4 d6 [2] fa f4 [2] ee ef [2] e1 f5 [2] ff e8 [2] fd e9 [2] e6 ef [2] fa e8 [2] e6 c7 }

  condition:
    any of them
}