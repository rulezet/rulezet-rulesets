rule TTP_XOR_MULT_DOSStub_6d6f {
  strings:
    $key_6d6f = { 39 07 [2] 4d 1f [2] 0a 1d [2] 4d 0c [2] 03 00 [2] 0f 0a [2] 18 01 [2] 03 4f [2] 3e }

  condition:
    any of them
}