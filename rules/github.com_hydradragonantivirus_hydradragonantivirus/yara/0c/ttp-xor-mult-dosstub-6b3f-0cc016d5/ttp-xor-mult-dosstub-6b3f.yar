rule TTP_XOR_MULT_DOSStub_6b3f {
  strings:
    $key_6b3f = { 3f 57 [2] 4b 4f [2] 0c 4d [2] 4b 5c [2] 05 50 [2] 09 5a [2] 1e 51 [2] 05 1f [2] 38 }

  condition:
    any of them
}