rule TTP_XOR_QUAD_CurrentVersionRun_9821 {
  strings:
    $key_9821 = { cb 4e [2] ef 40 [2] c4 6c [2] ea 4e [2] fe 55 [2] f1 4f [2] ef 52 [2] ed 53 [2] f6 55 [2] ea 52 [2] f6 7d }

  condition:
    any of them
}