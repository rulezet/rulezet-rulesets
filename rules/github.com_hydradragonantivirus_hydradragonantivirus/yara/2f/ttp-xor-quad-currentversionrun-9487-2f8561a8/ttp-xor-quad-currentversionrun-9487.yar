rule TTP_XOR_QUAD_CurrentVersionRun_9487 {
  strings:
    $key_9487 = { c7 e8 [2] e3 e6 [2] c8 ca [2] e6 e8 [2] f2 f3 [2] fd e9 [2] e3 f4 [2] e1 f5 [2] fa f3 [2] e6 f4 [2] fa db }

  condition:
    any of them
}