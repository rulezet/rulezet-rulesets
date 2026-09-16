rule TTP_XOR_MULT_DOSStub_3b7c {
  strings:
    $key_3b7c = { 6f 14 [2] 1b 0c [2] 5c 0e [2] 1b 1f [2] 55 13 [2] 59 19 [2] 4e 12 [2] 55 5c [2] 68 }

  condition:
    any of them
}