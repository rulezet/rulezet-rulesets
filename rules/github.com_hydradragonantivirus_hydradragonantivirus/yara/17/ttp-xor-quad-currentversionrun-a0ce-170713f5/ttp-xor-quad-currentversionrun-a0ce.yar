rule TTP_XOR_QUAD_CurrentVersionRun_a0ce {
  strings:
    $key_a0ce = { f3 a1 [2] d7 af [2] fc 83 [2] d2 a1 [2] c6 ba [2] c9 a0 [2] d7 bd [2] d5 bc [2] ce ba [2] d2 bd [2] ce 92 }

  condition:
    any of them
}