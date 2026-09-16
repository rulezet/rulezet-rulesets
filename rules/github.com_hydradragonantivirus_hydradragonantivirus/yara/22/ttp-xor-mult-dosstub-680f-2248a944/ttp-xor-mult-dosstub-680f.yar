rule TTP_XOR_MULT_DOSStub_680f {
  strings:
    $key_680f = { 3c 67 [2] 48 7f [2] 0f 7d [2] 48 6c [2] 06 60 [2] 0a 6a [2] 1d 61 [2] 06 2f [2] 3b }

  condition:
    any of them
}