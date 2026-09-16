rule TTP_XOR_MULT_DOSStub_2b7c {
  strings:
    $key_2b7c = { 7f 14 [2] 0b 0c [2] 4c 0e [2] 0b 1f [2] 45 13 [2] 49 19 [2] 5e 12 [2] 45 5c [2] 78 }

  condition:
    any of them
}