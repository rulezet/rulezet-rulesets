rule TTP_XOR_MULT_DOSStub_6a17 {
  strings:
    $key_6a17 = { 3e 7f [2] 4a 67 [2] 0d 65 [2] 4a 74 [2] 04 78 [2] 08 72 [2] 1f 79 [2] 04 37 [2] 39 }

  condition:
    any of them
}