rule TTP_XOR_MULT_DOSStub_5b1f {
  strings:
    $key_5b1f = { 0f 77 [2] 7b 6f [2] 3c 6d [2] 7b 7c [2] 35 70 [2] 39 7a [2] 2e 71 [2] 35 3f [2] 08 }

  condition:
    any of them
}