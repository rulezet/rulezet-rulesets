rule TTP_XOR_MULT_DOSStub_48b2 {
  strings:
    $key_48b2 = { 1c da [2] 68 c2 [2] 2f c0 [2] 68 d1 [2] 26 dd [2] 2a d7 [2] 3d dc [2] 26 92 [2] 1b }

  condition:
    any of them
}