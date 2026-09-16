rule TTP_XOR_MULT_DOSStub_5b6f {
  strings:
    $key_5b6f = { 0f 07 [2] 7b 1f [2] 3c 1d [2] 7b 0c [2] 35 00 [2] 39 0a [2] 2e 01 [2] 35 4f [2] 08 }

  condition:
    any of them
}