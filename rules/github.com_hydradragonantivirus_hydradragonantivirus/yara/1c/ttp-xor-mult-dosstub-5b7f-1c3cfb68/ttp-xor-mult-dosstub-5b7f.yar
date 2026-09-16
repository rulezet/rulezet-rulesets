rule TTP_XOR_MULT_DOSStub_5b7f {
  strings:
    $key_5b7f = { 0f 17 [2] 7b 0f [2] 3c 0d [2] 7b 1c [2] 35 10 [2] 39 1a [2] 2e 11 [2] 35 5f [2] 08 }

  condition:
    any of them
}