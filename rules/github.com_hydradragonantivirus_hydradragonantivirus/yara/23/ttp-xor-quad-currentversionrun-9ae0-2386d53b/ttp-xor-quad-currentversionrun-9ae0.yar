rule TTP_XOR_QUAD_CurrentVersionRun_9ae0 {
  strings:
    $key_9ae0 = { c9 8f [2] ed 81 [2] c6 ad [2] e8 8f [2] fc 94 [2] f3 8e [2] ed 93 [2] ef 92 [2] f4 94 [2] e8 93 [2] f4 bc }

  condition:
    any of them
}