rule TTP_XOR_MULT_DOSStub_6995 {
  strings:
    $key_6995 = { 3d fd [2] 49 e5 [2] 0e e7 [2] 49 f6 [2] 07 fa [2] 0b f0 [2] 1c fb [2] 07 b5 [2] 3a }

  condition:
    any of them
}