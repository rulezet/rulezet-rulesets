rule TTP_XOR_QUAD_CurrentVersionRun_57ce {
  strings:
    $key_57ce = { 04 a1 [2] 20 af [2] 0b 83 [2] 25 a1 [2] 31 ba [2] 3e a0 [2] 20 bd [2] 22 bc [2] 39 ba [2] 25 bd [2] 39 92 }

  condition:
    any of them
}