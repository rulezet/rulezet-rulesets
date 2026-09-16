rule TTP_XOR_MULT_DOSStub_e239 {
  strings:
    $key_e239 = { b6 51 [2] c2 49 [2] 85 4b [2] c2 5a [2] 8c 56 [2] 80 5c [2] 97 57 [2] 8c 19 [2] b1 }

  condition:
    any of them
}