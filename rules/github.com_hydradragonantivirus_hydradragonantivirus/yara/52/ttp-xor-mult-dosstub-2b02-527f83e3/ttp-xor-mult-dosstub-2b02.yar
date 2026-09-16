rule TTP_XOR_MULT_DOSStub_2b02 {
  strings:
    $key_2b02 = { 7f 6a [2] 0b 72 [2] 4c 70 [2] 0b 61 [2] 45 6d [2] 49 67 [2] 5e 6c [2] 45 22 [2] 78 }

  condition:
    any of them
}