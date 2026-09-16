rule TTP_XOR_QUAD_CurrentVersionRun_9811 {
  strings:
    $key_9811 = { cb 7e [2] ef 70 [2] c4 5c [2] ea 7e [2] fe 65 [2] f1 7f [2] ef 62 [2] ed 63 [2] f6 65 [2] ea 62 [2] f6 4d }

  condition:
    any of them
}