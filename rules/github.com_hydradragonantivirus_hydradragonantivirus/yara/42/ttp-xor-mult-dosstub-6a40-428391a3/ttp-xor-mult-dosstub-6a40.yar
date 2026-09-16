rule TTP_XOR_MULT_DOSStub_6a40 {
  strings:
    $key_6a40 = { 3e 28 [2] 4a 30 [2] 0d 32 [2] 4a 23 [2] 04 2f [2] 08 25 [2] 1f 2e [2] 04 60 [2] 39 }

  condition:
    any of them
}