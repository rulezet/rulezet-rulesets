rule TTP_XOR_MULT_DOSStub_357c {
  strings:
    $key_357c = { 61 14 [2] 15 0c [2] 52 0e [2] 15 1f [2] 5b 13 [2] 57 19 [2] 40 12 [2] 5b 5c [2] 66 }

  condition:
    any of them
}