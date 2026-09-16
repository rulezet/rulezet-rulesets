rule TTP_XOR_QUAD_CurrentVersionRun_9653 {
  strings:
    $key_9653 = { c5 3c [2] e1 32 [2] ca 1e [2] e4 3c [2] f0 27 [2] ff 3d [2] e1 20 [2] e3 21 [2] f8 27 [2] e4 20 [2] f8 0f }

  condition:
    any of them
}