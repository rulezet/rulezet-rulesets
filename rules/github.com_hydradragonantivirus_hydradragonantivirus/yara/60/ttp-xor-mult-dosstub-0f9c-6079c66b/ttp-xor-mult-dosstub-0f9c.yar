rule TTP_XOR_MULT_DOSStub_0f9c {
  strings:
    $key_0f9c = { 5b f4 [2] 2f ec [2] 68 ee [2] 2f ff [2] 61 f3 [2] 6d f9 [2] 7a f2 [2] 61 bc [2] 5c }

  condition:
    any of them
}