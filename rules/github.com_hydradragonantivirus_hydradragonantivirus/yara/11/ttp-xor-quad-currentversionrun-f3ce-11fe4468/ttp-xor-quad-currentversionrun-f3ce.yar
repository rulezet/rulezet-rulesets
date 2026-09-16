rule TTP_XOR_QUAD_CurrentVersionRun_f3ce {
  strings:
    $key_f3ce = { a0 a1 [2] 84 af [2] af 83 [2] 81 a1 [2] 95 ba [2] 9a a0 [2] 84 bd [2] 86 bc [2] 9d ba [2] 81 bd [2] 9d 92 }

  condition:
    any of them
}