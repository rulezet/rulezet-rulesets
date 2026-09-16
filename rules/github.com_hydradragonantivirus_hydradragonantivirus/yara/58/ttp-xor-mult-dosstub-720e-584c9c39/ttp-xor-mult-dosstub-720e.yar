rule TTP_XOR_MULT_DOSStub_720e {
  strings:
    $key_720e = { 26 66 [2] 52 7e [2] 15 7c [2] 52 6d [2] 1c 61 [2] 10 6b [2] 07 60 [2] 1c 2e [2] 21 }

  condition:
    any of them
}