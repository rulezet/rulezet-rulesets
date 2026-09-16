rule TTP_XOR_MULT_DOSStub_2c0e {
  strings:
    $key_2c0e = { 78 66 [2] 0c 7e [2] 4b 7c [2] 0c 6d [2] 42 61 [2] 4e 6b [2] 59 60 [2] 42 2e [2] 7f }

  condition:
    any of them
}