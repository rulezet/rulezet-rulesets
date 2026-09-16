rule TTP_XOR_MULT_DOSStub_488d {
  strings:
    $key_488d = { 1c e5 [2] 68 fd [2] 2f ff [2] 68 ee [2] 26 e2 [2] 2a e8 [2] 3d e3 [2] 26 ad [2] 1b }

  condition:
    any of them
}