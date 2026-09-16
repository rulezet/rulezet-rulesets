rule TTP_XOR_MULT_DOSStub_716f {
  strings:
    $key_716f = { 25 07 [2] 51 1f [2] 16 1d [2] 51 0c [2] 1f 00 [2] 13 0a [2] 04 01 [2] 1f 4f [2] 22 }

  condition:
    any of them
}