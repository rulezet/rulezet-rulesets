rule TTP_XOR_MULT_DOSStub_f4ed {
  strings:
    $key_f4ed = { a0 85 [2] d4 9d [2] 93 9f [2] d4 8e [2] 9a 82 [2] 96 88 [2] 81 83 [2] 9a cd [2] a7 }

  condition:
    any of them
}