rule TTP_XOR_QUAD_CurrentVersionRun_98f2 {
  strings:
    $key_98f2 = { cb 9d [2] ef 93 [2] c4 bf [2] ea 9d [2] fe 86 [2] f1 9c [2] ef 81 [2] ed 80 [2] f6 86 [2] ea 81 [2] f6 ae }

  condition:
    any of them
}