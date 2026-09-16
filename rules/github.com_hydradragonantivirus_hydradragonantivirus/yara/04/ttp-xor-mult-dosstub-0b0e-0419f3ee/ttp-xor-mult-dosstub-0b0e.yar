rule TTP_XOR_MULT_DOSStub_0b0e {
  strings:
    $key_0b0e = { 5f 66 [2] 2b 7e [2] 6c 7c [2] 2b 6d [2] 65 61 [2] 69 6b [2] 7e 60 [2] 65 2e [2] 58 }

  condition:
    any of them
}