rule TTP_XOR_QUAD_CurrentVersionRun_e666 {
  strings:
    $key_e666 = { b5 09 [2] 91 07 [2] ba 2b [2] 94 09 [2] 80 12 [2] 8f 08 [2] 91 15 [2] 93 14 [2] 88 12 [2] 94 15 [2] 88 3a }

  condition:
    any of them
}