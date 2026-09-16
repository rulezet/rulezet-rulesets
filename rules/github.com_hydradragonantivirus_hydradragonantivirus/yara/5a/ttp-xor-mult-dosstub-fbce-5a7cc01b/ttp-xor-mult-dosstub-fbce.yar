rule TTP_XOR_MULT_DOSStub_fbce {
  strings:
    $key_fbce = { af a6 [2] db be [2] 9c bc [2] db ad [2] 95 a1 [2] 99 ab [2] 8e a0 [2] 95 ee [2] a8 }

  condition:
    any of them
}