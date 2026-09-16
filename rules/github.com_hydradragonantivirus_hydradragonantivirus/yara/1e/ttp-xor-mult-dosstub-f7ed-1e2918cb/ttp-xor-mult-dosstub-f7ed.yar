rule TTP_XOR_MULT_DOSStub_f7ed {
  strings:
    $key_f7ed = { a3 85 [2] d7 9d [2] 90 9f [2] d7 8e [2] 99 82 [2] 95 88 [2] 82 83 [2] 99 cd [2] a4 }

  condition:
    any of them
}