rule TTP_XOR_MULT_DOSStub_1f9c {
  strings:
    $key_1f9c = { 4b f4 [2] 3f ec [2] 78 ee [2] 3f ff [2] 71 f3 [2] 7d f9 [2] 6a f2 [2] 71 bc [2] 4c }

  condition:
    any of them
}