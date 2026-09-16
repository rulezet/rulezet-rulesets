rule TTP_XOR_MULT_DOSStub_bb51 {
  strings:
    $key_bb51 = { ef 39 [2] 9b 21 [2] dc 23 [2] 9b 32 [2] d5 3e [2] d9 34 [2] ce 3f [2] d5 71 [2] e8 }

  condition:
    any of them
}