rule TTP_XOR_MULT_DOSStub_f573 {
  strings:
    $key_f573 = { a1 1b [2] d5 03 [2] 92 01 [2] d5 10 [2] 9b 1c [2] 97 16 [2] 80 1d [2] 9b 53 [2] a6 }

  condition:
    any of them
}