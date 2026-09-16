rule TTP_XOR_MULT_DOSStub_014c {
  strings:
    $key_014c = { 55 24 [2] 21 3c [2] 66 3e [2] 21 2f [2] 6f 23 [2] 63 29 [2] 74 22 [2] 6f 6c [2] 52 }

  condition:
    any of them
}