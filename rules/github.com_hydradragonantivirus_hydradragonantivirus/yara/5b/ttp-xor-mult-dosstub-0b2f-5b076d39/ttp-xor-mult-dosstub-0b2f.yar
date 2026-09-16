rule TTP_XOR_MULT_DOSStub_0b2f {
  strings:
    $key_0b2f = { 5f 47 [2] 2b 5f [2] 6c 5d [2] 2b 4c [2] 65 40 [2] 69 4a [2] 7e 41 [2] 65 0f [2] 58 }

  condition:
    any of them
}