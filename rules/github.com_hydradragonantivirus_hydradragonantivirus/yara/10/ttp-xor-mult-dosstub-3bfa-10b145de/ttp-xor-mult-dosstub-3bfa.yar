rule TTP_XOR_MULT_DOSStub_3bfa {
  strings:
    $key_3bfa = { 6f 92 [2] 1b 8a [2] 5c 88 [2] 1b 99 [2] 55 95 [2] 59 9f [2] 4e 94 [2] 55 da [2] 68 }

  condition:
    any of them
}