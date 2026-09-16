rule TTP_XOR_MULT_DOSStub_353f {
  strings:
    $key_353f = { 61 57 [2] 15 4f [2] 52 4d [2] 15 5c [2] 5b 50 [2] 57 5a [2] 40 51 [2] 5b 1f [2] 66 }

  condition:
    any of them
}