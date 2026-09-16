rule TTP_XOR_QUAD_CurrentVersionRun_98a3 {
  strings:
    $key_98a3 = { cb cc [2] ef c2 [2] c4 ee [2] ea cc [2] fe d7 [2] f1 cd [2] ef d0 [2] ed d1 [2] f6 d7 [2] ea d0 [2] f6 ff }

  condition:
    any of them
}