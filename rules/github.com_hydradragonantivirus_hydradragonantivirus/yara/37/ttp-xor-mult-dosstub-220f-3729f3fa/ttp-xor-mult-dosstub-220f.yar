rule TTP_XOR_MULT_DOSStub_220f {
  strings:
    $key_220f = { 76 67 [2] 02 7f [2] 45 7d [2] 02 6c [2] 4c 60 [2] 40 6a [2] 57 61 [2] 4c 2f [2] 71 }

  condition:
    any of them
}