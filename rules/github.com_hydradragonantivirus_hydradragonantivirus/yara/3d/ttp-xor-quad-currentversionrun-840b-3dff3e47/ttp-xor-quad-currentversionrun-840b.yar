rule TTP_XOR_QUAD_CurrentVersionRun_840b {
  strings:
    $key_840b = { d7 64 [2] f3 6a [2] d8 46 [2] f6 64 [2] e2 7f [2] ed 65 [2] f3 78 [2] f1 79 [2] ea 7f [2] f6 78 [2] ea 57 }

  condition:
    any of them
}