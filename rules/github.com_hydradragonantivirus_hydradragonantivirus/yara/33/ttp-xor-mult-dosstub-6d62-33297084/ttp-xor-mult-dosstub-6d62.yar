rule TTP_XOR_MULT_DOSStub_6d62 {
  strings:
    $key_6d62 = { 39 0a [2] 4d 12 [2] 0a 10 [2] 4d 01 [2] 03 0d [2] 0f 07 [2] 18 0c [2] 03 42 [2] 3e }

  condition:
    any of them
}