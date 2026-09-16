rule TTP_XOR_MULT_DOSStub_f50c {
  strings:
    $key_f50c = { a1 64 [2] d5 7c [2] 92 7e [2] d5 6f [2] 9b 63 [2] 97 69 [2] 80 62 [2] 9b 2c [2] a6 }

  condition:
    any of them
}