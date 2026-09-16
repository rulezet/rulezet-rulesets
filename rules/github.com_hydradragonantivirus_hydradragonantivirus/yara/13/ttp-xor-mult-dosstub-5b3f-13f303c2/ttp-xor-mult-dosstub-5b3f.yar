rule TTP_XOR_MULT_DOSStub_5b3f {
  strings:
    $key_5b3f = { 0f 57 [2] 7b 4f [2] 3c 4d [2] 7b 5c [2] 35 50 [2] 39 5a [2] 2e 51 [2] 35 1f [2] 08 }

  condition:
    any of them
}