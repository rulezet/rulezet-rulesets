rule TTP_XOR_MULT_DOSStub_6a50 {
  strings:
    $key_6a50 = { 3e 38 [2] 4a 20 [2] 0d 22 [2] 4a 33 [2] 04 3f [2] 08 35 [2] 1f 3e [2] 04 70 [2] 39 }

  condition:
    any of them
}