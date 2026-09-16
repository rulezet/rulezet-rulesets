rule TTP_XOR_MULT_DOSStub_096f {
  strings:
    $key_096f = { 5d 07 [2] 29 1f [2] 6e 1d [2] 29 0c [2] 67 00 [2] 6b 0a [2] 7c 01 [2] 67 4f [2] 5a }

  condition:
    any of them
}