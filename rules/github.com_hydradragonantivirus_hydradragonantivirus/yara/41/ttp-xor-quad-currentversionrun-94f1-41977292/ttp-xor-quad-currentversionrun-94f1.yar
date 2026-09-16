rule TTP_XOR_QUAD_CurrentVersionRun_94f1 {
  strings:
    $key_94f1 = { c7 9e [2] e3 90 [2] c8 bc [2] e6 9e [2] f2 85 [2] fd 9f [2] e3 82 [2] e1 83 [2] fa 85 [2] e6 82 [2] fa ad }

  condition:
    any of them
}