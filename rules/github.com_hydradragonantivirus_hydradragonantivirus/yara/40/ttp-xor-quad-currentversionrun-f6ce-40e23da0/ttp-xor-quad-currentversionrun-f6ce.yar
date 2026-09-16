rule TTP_XOR_QUAD_CurrentVersionRun_f6ce {
  strings:
    $key_f6ce = { a5 a1 [2] 81 af [2] aa 83 [2] 84 a1 [2] 90 ba [2] 9f a0 [2] 81 bd [2] 83 bc [2] 98 ba [2] 84 bd [2] 98 92 }

  condition:
    any of them
}