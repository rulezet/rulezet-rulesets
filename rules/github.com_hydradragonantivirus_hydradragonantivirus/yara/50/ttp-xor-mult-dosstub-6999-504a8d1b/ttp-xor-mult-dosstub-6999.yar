rule TTP_XOR_MULT_DOSStub_6999 {
  strings:
    $key_6999 = { 3d f1 [2] 49 e9 [2] 0e eb [2] 49 fa [2] 07 f6 [2] 0b fc [2] 1c f7 [2] 07 b9 [2] 3a }

  condition:
    any of them
}