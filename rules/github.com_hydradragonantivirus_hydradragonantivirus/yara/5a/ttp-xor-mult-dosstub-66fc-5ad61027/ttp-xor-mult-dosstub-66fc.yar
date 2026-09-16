rule TTP_XOR_MULT_DOSStub_66fc {
  strings:
    $key_66fc = { 32 94 [2] 46 8c [2] 01 8e [2] 46 9f [2] 08 93 [2] 04 99 [2] 13 92 [2] 08 dc [2] 35 }

  condition:
    any of them
}