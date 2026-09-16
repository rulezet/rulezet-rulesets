rule TTP_XOR_QUAD_CurrentVersionRun_942a {
  strings:
    $key_942a = { c7 45 [2] e3 4b [2] c8 67 [2] e6 45 [2] f2 5e [2] fd 44 [2] e3 59 [2] e1 58 [2] fa 5e [2] e6 59 [2] fa 76 }

  condition:
    any of them
}