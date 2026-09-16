rule TTP_XOR_MULT_DOSStub_0965 {
  strings:
    $key_0965 = { 5d 0d [2] 29 15 [2] 6e 17 [2] 29 06 [2] 67 0a [2] 6b 00 [2] 7c 0b [2] 67 45 [2] 5a }

  condition:
    any of them
}