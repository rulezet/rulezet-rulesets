rule TTP_XOR_MULT_DOSStub_2bfa {
  strings:
    $key_2bfa = { 7f 92 [2] 0b 8a [2] 4c 88 [2] 0b 99 [2] 45 95 [2] 49 9f [2] 5e 94 [2] 45 da [2] 78 }

  condition:
    any of them
}