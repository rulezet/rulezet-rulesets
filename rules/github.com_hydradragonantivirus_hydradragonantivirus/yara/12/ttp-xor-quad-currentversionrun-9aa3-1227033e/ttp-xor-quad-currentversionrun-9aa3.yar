rule TTP_XOR_QUAD_CurrentVersionRun_9aa3 {
  strings:
    $key_9aa3 = { c9 cc [2] ed c2 [2] c6 ee [2] e8 cc [2] fc d7 [2] f3 cd [2] ed d0 [2] ef d1 [2] f4 d7 [2] e8 d0 [2] f4 ff }

  condition:
    any of them
}