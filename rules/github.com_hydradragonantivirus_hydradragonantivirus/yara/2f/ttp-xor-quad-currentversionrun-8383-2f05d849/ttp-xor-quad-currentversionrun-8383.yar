rule TTP_XOR_QUAD_CurrentVersionRun_8383 {
  strings:
    $key_8383 = { d0 ec [2] f4 e2 [2] df ce [2] f1 ec [2] e5 f7 [2] ea ed [2] f4 f0 [2] f6 f1 [2] ed f7 [2] f1 f0 [2] ed df }

  condition:
    any of them
}