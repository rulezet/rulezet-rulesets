rule TTP_XOR_QUAD_CurrentVersionRun_e1a3 {
  strings:
    $key_e1a3 = { b2 cc [2] 96 c2 [2] bd ee [2] 93 cc [2] 87 d7 [2] 88 cd [2] 96 d0 [2] 94 d1 [2] 8f d7 [2] 93 d0 [2] 8f ff }

  condition:
    any of them
}