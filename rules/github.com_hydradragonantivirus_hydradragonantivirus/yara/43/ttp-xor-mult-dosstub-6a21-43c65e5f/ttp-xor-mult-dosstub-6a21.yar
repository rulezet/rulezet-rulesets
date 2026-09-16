rule TTP_XOR_MULT_DOSStub_6a21 {
  strings:
    $key_6a21 = { 3e 49 [2] 4a 51 [2] 0d 53 [2] 4a 42 [2] 04 4e [2] 08 44 [2] 1f 4f [2] 04 01 [2] 39 }

  condition:
    any of them
}