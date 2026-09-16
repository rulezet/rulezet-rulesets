rule TTP_XOR_QUAD_CurrentVersionRun_9402 {
  strings:
    $key_9402 = { c7 6d [2] e3 63 [2] c8 4f [2] e6 6d [2] f2 76 [2] fd 6c [2] e3 71 [2] e1 70 [2] fa 76 [2] e6 71 [2] fa 5e }

  condition:
    any of them
}