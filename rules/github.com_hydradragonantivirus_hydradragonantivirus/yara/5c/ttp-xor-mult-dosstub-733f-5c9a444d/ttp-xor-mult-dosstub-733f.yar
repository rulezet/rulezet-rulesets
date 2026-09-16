rule TTP_XOR_MULT_DOSStub_733f {
  strings:
    $key_733f = { 27 57 [2] 53 4f [2] 14 4d [2] 53 5c [2] 1d 50 [2] 11 5a [2] 06 51 [2] 1d 1f [2] 20 }

  condition:
    any of them
}