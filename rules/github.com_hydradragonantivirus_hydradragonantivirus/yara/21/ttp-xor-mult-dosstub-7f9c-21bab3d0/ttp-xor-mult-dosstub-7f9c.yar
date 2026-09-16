rule TTP_XOR_MULT_DOSStub_7f9c {
  strings:
    $key_7f9c = { 2b f4 [2] 5f ec [2] 18 ee [2] 5f ff [2] 11 f3 [2] 1d f9 [2] 0a f2 [2] 11 bc [2] 2c }

  condition:
    any of them
}