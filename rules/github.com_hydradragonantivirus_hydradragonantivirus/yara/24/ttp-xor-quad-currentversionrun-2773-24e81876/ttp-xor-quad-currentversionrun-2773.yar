rule TTP_XOR_QUAD_CurrentVersionRun_2773 {
  strings:
    $key_2773 = { 74 1c [2] 50 12 [2] 7b 3e [2] 55 1c [2] 41 07 [2] 4e 1d [2] 50 00 [2] 52 01 [2] 49 07 [2] 55 00 [2] 49 2f }

  condition:
    any of them
}