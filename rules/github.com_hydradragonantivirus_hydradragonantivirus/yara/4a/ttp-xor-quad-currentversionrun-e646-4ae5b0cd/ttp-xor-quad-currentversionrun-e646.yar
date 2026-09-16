rule TTP_XOR_QUAD_CurrentVersionRun_e646 {
  strings:
    $key_e646 = { b5 29 [2] 91 27 [2] ba 0b [2] 94 29 [2] 80 32 [2] 8f 28 [2] 91 35 [2] 93 34 [2] 88 32 [2] 94 35 [2] 88 1a }

  condition:
    any of them
}