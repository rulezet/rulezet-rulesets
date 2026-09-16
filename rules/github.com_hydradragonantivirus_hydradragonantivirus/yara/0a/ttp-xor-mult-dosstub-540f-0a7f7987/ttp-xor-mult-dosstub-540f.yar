rule TTP_XOR_MULT_DOSStub_540f {
  strings:
    $key_540f = { 00 67 [2] 74 7f [2] 33 7d [2] 74 6c [2] 3a 60 [2] 36 6a [2] 21 61 [2] 3a 2f [2] 07 }

  condition:
    any of them
}