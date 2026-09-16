rule TTP_XOR_MULT_DOSStub_080f {
  strings:
    $key_080f = { 5c 67 [2] 28 7f [2] 6f 7d [2] 28 6c [2] 66 60 [2] 6a 6a [2] 7d 61 [2] 66 2f [2] 5b }

  condition:
    any of them
}