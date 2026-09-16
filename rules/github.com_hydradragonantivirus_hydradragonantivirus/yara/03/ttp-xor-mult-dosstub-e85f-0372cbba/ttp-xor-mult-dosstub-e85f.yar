rule TTP_XOR_MULT_DOSStub_e85f {
  strings:
    $key_e85f = { bc 37 [2] c8 2f [2] 8f 2d [2] c8 3c [2] 86 30 [2] 8a 3a [2] 9d 31 [2] 86 7f [2] bb }

  condition:
    any of them
}