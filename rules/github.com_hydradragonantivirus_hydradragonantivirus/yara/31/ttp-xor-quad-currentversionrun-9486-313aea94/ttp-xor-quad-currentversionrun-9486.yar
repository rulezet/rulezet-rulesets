rule TTP_XOR_QUAD_CurrentVersionRun_9486 {
  strings:
    $key_9486 = { c7 e9 [2] e3 e7 [2] c8 cb [2] e6 e9 [2] f2 f2 [2] fd e8 [2] e3 f5 [2] e1 f4 [2] fa f2 [2] e6 f5 [2] fa da }

  condition:
    any of them
}