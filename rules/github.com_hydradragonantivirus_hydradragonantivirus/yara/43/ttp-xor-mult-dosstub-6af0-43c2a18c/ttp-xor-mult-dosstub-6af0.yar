rule TTP_XOR_MULT_DOSStub_6af0 {
  strings:
    $key_6af0 = { 3e 98 [2] 4a 80 [2] 0d 82 [2] 4a 93 [2] 04 9f [2] 08 95 [2] 1f 9e [2] 04 d0 [2] 39 }

  condition:
    any of them
}