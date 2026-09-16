rule TTP_XOR_MULT_DOSStub_e202 {
  strings:
    $key_e202 = { b6 6a [2] c2 72 [2] 85 70 [2] c2 61 [2] 8c 6d [2] 80 67 [2] 97 6c [2] 8c 22 [2] b1 }

  condition:
    any of them
}