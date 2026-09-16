rule TTP_XOR_MULT_DOSStub_f5ed {
  strings:
    $key_f5ed = { a1 85 [2] d5 9d [2] 92 9f [2] d5 8e [2] 9b 82 [2] 97 88 [2] 80 83 [2] 9b cd [2] a6 }

  condition:
    any of them
}