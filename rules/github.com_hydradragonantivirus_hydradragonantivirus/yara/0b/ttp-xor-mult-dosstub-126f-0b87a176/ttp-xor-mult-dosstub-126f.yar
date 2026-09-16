rule TTP_XOR_MULT_DOSStub_126f {
  strings:
    $key_126f = { 46 07 [2] 32 1f [2] 75 1d [2] 32 0c [2] 7c 00 [2] 70 0a [2] 67 01 [2] 7c 4f [2] 41 }

  condition:
    any of them
}