rule TTP_XOR_MULT_DOSStub_5221 {
  strings:
    $key_5221 = { 06 49 [2] 72 51 [2] 35 53 [2] 72 42 [2] 3c 4e [2] 30 44 [2] 27 4f [2] 3c 01 [2] 01 }

  condition:
    any of them
}