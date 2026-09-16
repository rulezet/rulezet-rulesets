rule TTP_XOR_MULT_DOSStub_6a11 {
  strings:
    $key_6a11 = { 3e 79 [2] 4a 61 [2] 0d 63 [2] 4a 72 [2] 04 7e [2] 08 74 [2] 1f 7f [2] 04 31 [2] 39 }

  condition:
    any of them
}