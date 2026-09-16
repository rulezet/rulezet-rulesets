rule TTP_XOR_MULT_DOSStub_452f {
  strings:
    $key_452f = { 11 47 [2] 65 5f [2] 22 5d [2] 65 4c [2] 2b 40 [2] 27 4a [2] 30 41 [2] 2b 0f [2] 16 }

  condition:
    any of them
}