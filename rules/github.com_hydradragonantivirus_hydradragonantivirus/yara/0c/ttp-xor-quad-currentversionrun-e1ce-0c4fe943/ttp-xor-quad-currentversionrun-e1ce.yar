rule TTP_XOR_QUAD_CurrentVersionRun_e1ce {
  strings:
    $key_e1ce = { b2 a1 [2] 96 af [2] bd 83 [2] 93 a1 [2] 87 ba [2] 88 a0 [2] 96 bd [2] 94 bc [2] 8f ba [2] 93 bd [2] 8f 92 }

  condition:
    any of them
}