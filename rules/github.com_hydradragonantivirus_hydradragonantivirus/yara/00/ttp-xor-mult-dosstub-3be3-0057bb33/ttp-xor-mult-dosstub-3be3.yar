rule TTP_XOR_MULT_DOSStub_3be3 {
  strings:
    $key_3be3 = { 6f 8b [2] 1b 93 [2] 5c 91 [2] 1b 80 [2] 55 8c [2] 59 86 [2] 4e 8d [2] 55 c3 [2] 68 }

  condition:
    any of them
}