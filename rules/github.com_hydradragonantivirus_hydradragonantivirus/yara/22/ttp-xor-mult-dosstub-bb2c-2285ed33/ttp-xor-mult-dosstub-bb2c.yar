rule TTP_XOR_MULT_DOSStub_bb2c {
  strings:
    $key_bb2c = { ef 44 [2] 9b 5c [2] dc 5e [2] 9b 4f [2] d5 43 [2] d9 49 [2] ce 42 [2] d5 0c [2] e8 }

  condition:
    any of them
}