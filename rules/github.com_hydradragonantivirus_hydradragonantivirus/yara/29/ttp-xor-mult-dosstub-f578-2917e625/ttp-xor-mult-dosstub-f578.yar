rule TTP_XOR_MULT_DOSStub_f578 {
  strings:
    $key_f578 = { a1 10 [2] d5 08 [2] 92 0a [2] d5 1b [2] 9b 17 [2] 97 1d [2] 80 16 [2] 9b 58 [2] a6 }

  condition:
    any of them
}