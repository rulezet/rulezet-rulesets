rule TTP_XOR_MULT_DOSStub_6a61 {
  strings:
    $key_6a61 = { 3e 09 [2] 4a 11 [2] 0d 13 [2] 4a 02 [2] 04 0e [2] 08 04 [2] 1f 0f [2] 04 41 [2] 39 }

  condition:
    any of them
}