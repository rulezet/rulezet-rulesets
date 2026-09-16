rule TTP_XOR_MULT_DOSStub_655f {
  strings:
    $key_655f = { 31 37 [2] 45 2f [2] 02 2d [2] 45 3c [2] 0b 30 [2] 07 3a [2] 10 31 [2] 0b 7f [2] 36 }

  condition:
    any of them
}