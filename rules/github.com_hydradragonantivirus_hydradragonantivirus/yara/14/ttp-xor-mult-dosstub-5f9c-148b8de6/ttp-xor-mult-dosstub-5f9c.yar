rule TTP_XOR_MULT_DOSStub_5f9c {
  strings:
    $key_5f9c = { 0b f4 [2] 7f ec [2] 38 ee [2] 7f ff [2] 31 f3 [2] 3d f9 [2] 2a f2 [2] 31 bc [2] 0c }

  condition:
    any of them
}