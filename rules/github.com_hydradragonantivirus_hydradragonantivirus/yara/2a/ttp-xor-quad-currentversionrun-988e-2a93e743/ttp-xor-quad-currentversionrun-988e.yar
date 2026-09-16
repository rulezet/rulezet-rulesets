rule TTP_XOR_QUAD_CurrentVersionRun_988e {
  strings:
    $key_988e = { cb e1 [2] ef ef [2] c4 c3 [2] ea e1 [2] fe fa [2] f1 e0 [2] ef fd [2] ed fc [2] f6 fa [2] ea fd [2] f6 d2 }

  condition:
    any of them
}