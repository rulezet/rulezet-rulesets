rule TTP_XOR_QUAD_CurrentVersionRun_f7ce {
  strings:
    $key_f7ce = { a4 a1 [2] 80 af [2] ab 83 [2] 85 a1 [2] 91 ba [2] 9e a0 [2] 80 bd [2] 82 bc [2] 99 ba [2] 85 bd [2] 99 92 }

  condition:
    any of them
}