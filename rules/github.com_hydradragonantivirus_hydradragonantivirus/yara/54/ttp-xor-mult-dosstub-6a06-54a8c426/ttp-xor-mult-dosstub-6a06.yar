rule TTP_XOR_MULT_DOSStub_6a06 {
  strings:
    $key_6a06 = { 3e 6e [2] 4a 76 [2] 0d 74 [2] 4a 65 [2] 04 69 [2] 08 63 [2] 1f 68 [2] 04 26 [2] 39 }

  condition:
    any of them
}