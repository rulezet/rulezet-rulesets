rule TTP_XOR_QUAD_CurrentVersionRun_9302 {
  strings:
    $key_9302 = { c0 6d [2] e4 63 [2] cf 4f [2] e1 6d [2] f5 76 [2] fa 6c [2] e4 71 [2] e6 70 [2] fd 76 [2] e1 71 [2] fd 5e }

  condition:
    any of them
}