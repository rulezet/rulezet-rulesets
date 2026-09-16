rule TTP_XOR_MULT_DOSStub_3b02 {
  strings:
    $key_3b02 = { 6f 6a [2] 1b 72 [2] 5c 70 [2] 1b 61 [2] 55 6d [2] 59 67 [2] 4e 6c [2] 55 22 [2] 68 }

  condition:
    any of them
}