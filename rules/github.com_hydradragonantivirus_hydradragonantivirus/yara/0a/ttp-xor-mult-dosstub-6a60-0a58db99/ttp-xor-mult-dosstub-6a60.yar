rule TTP_XOR_MULT_DOSStub_6a60 {
  strings:
    $key_6a60 = { 3e 08 [2] 4a 10 [2] 0d 12 [2] 4a 03 [2] 04 0f [2] 08 05 [2] 1f 0e [2] 04 40 [2] 39 }

  condition:
    any of them
}