rule TTP_XOR_MULT_DOSStub_710f {
  strings:
    $key_710f = { 25 67 [2] 51 7f [2] 16 7d [2] 51 6c [2] 1f 60 [2] 13 6a [2] 04 61 [2] 1f 2f [2] 22 }

  condition:
    any of them
}