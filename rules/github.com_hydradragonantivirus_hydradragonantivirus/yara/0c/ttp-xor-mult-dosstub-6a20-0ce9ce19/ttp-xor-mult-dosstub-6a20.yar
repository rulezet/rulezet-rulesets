rule TTP_XOR_MULT_DOSStub_6a20 {
  strings:
    $key_6a20 = { 3e 48 [2] 4a 50 [2] 0d 52 [2] 4a 43 [2] 04 4f [2] 08 45 [2] 1f 4e [2] 04 00 [2] 39 }

  condition:
    any of them
}