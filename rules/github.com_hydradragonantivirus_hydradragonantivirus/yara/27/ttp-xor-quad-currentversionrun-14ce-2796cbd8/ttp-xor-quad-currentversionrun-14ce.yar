rule TTP_XOR_QUAD_CurrentVersionRun_14ce {
  strings:
    $key_14ce = { 47 a1 [2] 63 af [2] 48 83 [2] 66 a1 [2] 72 ba [2] 7d a0 [2] 63 bd [2] 61 bc [2] 7a ba [2] 66 bd [2] 7a 92 }

  condition:
    any of them
}