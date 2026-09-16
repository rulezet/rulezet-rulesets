rule TTP_XOR_QUAD_CurrentVersionRun_e1a2 {
  strings:
    $key_e1a2 = { b2 cd [2] 96 c3 [2] bd ef [2] 93 cd [2] 87 d6 [2] 88 cc [2] 96 d1 [2] 94 d0 [2] 8f d6 [2] 93 d1 [2] 8f fe }

  condition:
    any of them
}