rule TTP_XOR_MULT_DOSStub_410f {
  strings:
    $key_410f = { 15 67 [2] 61 7f [2] 26 7d [2] 61 6c [2] 2f 60 [2] 23 6a [2] 34 61 [2] 2f 2f [2] 12 }

  condition:
    any of them
}