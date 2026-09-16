rule TTP_XOR_MULT_DOSStub_686f {
  strings:
    $key_686f = { 3c 07 [2] 48 1f [2] 0f 1d [2] 48 0c [2] 06 00 [2] 0a 0a [2] 1d 01 [2] 06 4f [2] 3b }

  condition:
    any of them
}