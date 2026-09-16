rule TTP_XOR_QUAD_CurrentVersionRun_937b {
  strings:
    $key_937b = { c0 14 [2] e4 1a [2] cf 36 [2] e1 14 [2] f5 0f [2] fa 15 [2] e4 08 [2] e6 09 [2] fd 0f [2] e1 08 [2] fd 27 }

  condition:
    any of them
}