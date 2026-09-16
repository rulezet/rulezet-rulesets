rule TTP_XOR_MULT_DOSStub_170f {
  strings:
    $key_170f = { 43 67 [2] 37 7f [2] 70 7d [2] 37 6c [2] 79 60 [2] 75 6a [2] 62 61 [2] 79 2f [2] 44 }

  condition:
    any of them
}