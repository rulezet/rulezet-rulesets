rule TTP_XOR_QUAD_CurrentVersionRun_9307 {
  strings:
    $key_9307 = { c0 68 [2] e4 66 [2] cf 4a [2] e1 68 [2] f5 73 [2] fa 69 [2] e4 74 [2] e6 75 [2] fd 73 [2] e1 74 [2] fd 5b }

  condition:
    any of them
}