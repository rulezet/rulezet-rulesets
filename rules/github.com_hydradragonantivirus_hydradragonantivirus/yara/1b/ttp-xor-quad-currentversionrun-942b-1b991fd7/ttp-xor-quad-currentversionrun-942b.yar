rule TTP_XOR_QUAD_CurrentVersionRun_942b {
  strings:
    $key_942b = { c7 44 [2] e3 4a [2] c8 66 [2] e6 44 [2] f2 5f [2] fd 45 [2] e3 58 [2] e1 59 [2] fa 5f [2] e6 58 [2] fa 77 }

  condition:
    any of them
}