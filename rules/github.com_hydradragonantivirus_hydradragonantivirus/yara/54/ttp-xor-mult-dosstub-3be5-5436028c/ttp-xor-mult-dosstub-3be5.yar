rule TTP_XOR_MULT_DOSStub_3be5 {
  strings:
    $key_3be5 = { 6f 8d [2] 1b 95 [2] 5c 97 [2] 1b 86 [2] 55 8a [2] 59 80 [2] 4e 8b [2] 55 c5 [2] 68 }

  condition:
    any of them
}