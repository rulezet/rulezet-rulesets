rule TTP_XOR_MULT_DOSStub_5b2f {
  strings:
    $key_5b2f = { 0f 47 [2] 7b 5f [2] 3c 5d [2] 7b 4c [2] 35 40 [2] 39 4a [2] 2e 41 [2] 35 0f [2] 08 }

  condition:
    any of them
}