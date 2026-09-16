rule TTP_XOR_QUAD_CurrentVersionRun_9396 {
  strings:
    $key_9396 = { c0 f9 [2] e4 f7 [2] cf db [2] e1 f9 [2] f5 e2 [2] fa f8 [2] e4 e5 [2] e6 e4 [2] fd e2 [2] e1 e5 [2] fd ca }

  condition:
    any of them
}