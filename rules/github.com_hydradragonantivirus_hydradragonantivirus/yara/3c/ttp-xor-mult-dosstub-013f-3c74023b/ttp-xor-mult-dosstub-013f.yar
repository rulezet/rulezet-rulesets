rule TTP_XOR_MULT_DOSStub_013f {
  strings:
    $key_013f = { 55 57 [2] 21 4f [2] 66 4d [2] 21 5c [2] 6f 50 [2] 63 5a [2] 74 51 [2] 6f 1f [2] 52 }

  condition:
    any of them
}