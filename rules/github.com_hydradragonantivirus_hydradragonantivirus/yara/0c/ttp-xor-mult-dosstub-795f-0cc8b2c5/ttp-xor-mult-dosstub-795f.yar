rule TTP_XOR_MULT_DOSStub_795f {
  strings:
    $key_795f = { 2d 37 [2] 59 2f [2] 1e 2d [2] 59 3c [2] 17 30 [2] 1b 3a [2] 0c 31 [2] 17 7f [2] 2a }

  condition:
    any of them
}