rule TTP_XOR_QUAD_CurrentVersionRun_93e3 {
  strings:
    $key_93e3 = { c0 8c [2] e4 82 [2] cf ae [2] e1 8c [2] f5 97 [2] fa 8d [2] e4 90 [2] e6 91 [2] fd 97 [2] e1 90 [2] fd bf }

  condition:
    any of them
}