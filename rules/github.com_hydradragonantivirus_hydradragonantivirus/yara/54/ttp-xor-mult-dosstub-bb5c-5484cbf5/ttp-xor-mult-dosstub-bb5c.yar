rule TTP_XOR_MULT_DOSStub_bb5c {
  strings:
    $key_bb5c = { ef 34 [2] 9b 2c [2] dc 2e [2] 9b 3f [2] d5 33 [2] d9 39 [2] ce 32 [2] d5 7c [2] e8 }

  condition:
    any of them
}