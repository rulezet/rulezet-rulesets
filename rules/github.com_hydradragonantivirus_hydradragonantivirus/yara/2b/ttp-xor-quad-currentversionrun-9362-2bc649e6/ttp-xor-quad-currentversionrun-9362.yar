rule TTP_XOR_QUAD_CurrentVersionRun_9362 {
  strings:
    $key_9362 = { c0 0d [2] e4 03 [2] cf 2f [2] e1 0d [2] f5 16 [2] fa 0c [2] e4 11 [2] e6 10 [2] fd 16 [2] e1 11 [2] fd 3e }

  condition:
    any of them
}