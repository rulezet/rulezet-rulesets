rule TTP_XOR_QUAD_CurrentVersionRun_935b {
  strings:
    $key_935b = { c0 34 [2] e4 3a [2] cf 16 [2] e1 34 [2] f5 2f [2] fa 35 [2] e4 28 [2] e6 29 [2] fd 2f [2] e1 28 [2] fd 07 }

  condition:
    any of them
}