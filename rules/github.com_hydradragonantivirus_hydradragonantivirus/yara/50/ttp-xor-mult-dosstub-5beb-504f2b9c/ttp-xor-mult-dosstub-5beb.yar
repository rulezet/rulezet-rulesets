rule TTP_XOR_MULT_DOSStub_5beb {
  strings:
    $key_5beb = { 0f 83 [2] 7b 9b [2] 3c 99 [2] 7b 88 [2] 35 84 [2] 39 8e [2] 2e 85 [2] 35 cb [2] 08 }

  condition:
    any of them
}