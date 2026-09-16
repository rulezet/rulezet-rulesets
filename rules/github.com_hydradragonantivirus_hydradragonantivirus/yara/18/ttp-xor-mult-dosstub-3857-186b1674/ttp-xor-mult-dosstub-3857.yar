rule TTP_XOR_MULT_DOSStub_3857 {
  strings:
    $key_3857 = { 6c 3f [2] 18 27 [2] 5f 25 [2] 18 34 [2] 56 38 [2] 5a 32 [2] 4d 39 [2] 56 77 [2] 6b }

  condition:
    any of them
}