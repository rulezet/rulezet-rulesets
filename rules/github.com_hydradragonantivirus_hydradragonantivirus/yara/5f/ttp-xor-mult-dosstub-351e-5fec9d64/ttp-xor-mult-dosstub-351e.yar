rule TTP_XOR_MULT_DOSStub_351e {
  strings:
    $key_351e = { 61 76 [2] 15 6e [2] 52 6c [2] 15 7d [2] 5b 71 [2] 57 7b [2] 40 70 [2] 5b 3e [2] 66 }

  condition:
    any of them
}