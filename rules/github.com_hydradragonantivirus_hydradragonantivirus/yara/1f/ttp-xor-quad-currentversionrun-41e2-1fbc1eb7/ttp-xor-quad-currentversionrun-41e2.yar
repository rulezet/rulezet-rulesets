rule TTP_XOR_QUAD_CurrentVersionRun_41e2 {
  strings:
    $key_41e2 = { 12 8d [2] 36 83 [2] 1d af [2] 33 8d [2] 27 96 [2] 28 8c [2] 36 91 [2] 34 90 [2] 2f 96 [2] 33 91 [2] 2f be }

  condition:
    any of them
}