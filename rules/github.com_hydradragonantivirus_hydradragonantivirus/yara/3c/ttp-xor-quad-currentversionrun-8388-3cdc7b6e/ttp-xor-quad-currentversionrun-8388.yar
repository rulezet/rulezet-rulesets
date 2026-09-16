rule TTP_XOR_QUAD_CurrentVersionRun_8388 {
  strings:
    $key_8388 = { d0 e7 [2] f4 e9 [2] df c5 [2] f1 e7 [2] e5 fc [2] ea e6 [2] f4 fb [2] f6 fa [2] ed fc [2] f1 fb [2] ed d4 }

  condition:
    any of them
}