rule TTP_XOR_QUAD_CurrentVersionRun_8402 {
  strings:
    $key_8402 = { d7 6d [2] f3 63 [2] d8 4f [2] f6 6d [2] e2 76 [2] ed 6c [2] f3 71 [2] f1 70 [2] ea 76 [2] f6 71 [2] ea 5e }

  condition:
    any of them
}