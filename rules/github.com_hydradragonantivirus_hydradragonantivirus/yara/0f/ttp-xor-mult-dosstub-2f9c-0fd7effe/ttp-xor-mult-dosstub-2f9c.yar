rule TTP_XOR_MULT_DOSStub_2f9c {
  strings:
    $key_2f9c = { 7b f4 [2] 0f ec [2] 48 ee [2] 0f ff [2] 41 f3 [2] 4d f9 [2] 5a f2 [2] 41 bc [2] 7c }

  condition:
    any of them
}