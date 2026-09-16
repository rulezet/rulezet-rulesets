rule TTP_XOR_MULT_DOSStub_8aa0 {
  strings:
    $key_8aa0 = { de c8 [2] aa d0 [2] ed d2 [2] aa c3 [2] e4 cf [2] e8 c5 [2] ff ce [2] e4 80 [2] d9 }

  condition:
    any of them
}