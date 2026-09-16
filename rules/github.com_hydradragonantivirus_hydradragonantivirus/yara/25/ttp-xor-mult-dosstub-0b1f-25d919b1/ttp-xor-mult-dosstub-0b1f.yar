rule TTP_XOR_MULT_DOSStub_0b1f {
  strings:
    $key_0b1f = { 5f 77 [2] 2b 6f [2] 6c 6d [2] 2b 7c [2] 65 70 [2] 69 7a [2] 7e 71 [2] 65 3f [2] 58 }

  condition:
    any of them
}