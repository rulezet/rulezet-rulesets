rule TTP_XOR_MULT_DOSStub_6a76 {
  strings:
    $key_6a76 = { 3e 1e [2] 4a 06 [2] 0d 04 [2] 4a 15 [2] 04 19 [2] 08 13 [2] 1f 18 [2] 04 56 [2] 39 }

  condition:
    any of them
}