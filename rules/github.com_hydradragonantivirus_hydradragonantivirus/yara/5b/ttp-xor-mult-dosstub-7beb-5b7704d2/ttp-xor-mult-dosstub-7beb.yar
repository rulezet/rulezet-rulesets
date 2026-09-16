rule TTP_XOR_MULT_DOSStub_7beb {
  strings:
    $key_7beb = { 2f 83 [2] 5b 9b [2] 1c 99 [2] 5b 88 [2] 15 84 [2] 19 8e [2] 0e 85 [2] 15 cb [2] 28 }

  condition:
    any of them
}