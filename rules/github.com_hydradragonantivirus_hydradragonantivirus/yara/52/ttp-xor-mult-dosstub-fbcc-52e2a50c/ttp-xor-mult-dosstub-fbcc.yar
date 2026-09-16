rule TTP_XOR_MULT_DOSStub_fbcc {
  strings:
    $key_fbcc = { af a4 [2] db bc [2] 9c be [2] db af [2] 95 a3 [2] 99 a9 [2] 8e a2 [2] 95 ec [2] a8 }

  condition:
    any of them
}