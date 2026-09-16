rule TTP_XOR_MULT_DOSStub_2b5f {
  strings:
    $key_2b5f = { 7f 37 [2] 0b 2f [2] 4c 2d [2] 0b 3c [2] 45 30 [2] 49 3a [2] 5e 31 [2] 45 7f [2] 78 }

  condition:
    any of them
}