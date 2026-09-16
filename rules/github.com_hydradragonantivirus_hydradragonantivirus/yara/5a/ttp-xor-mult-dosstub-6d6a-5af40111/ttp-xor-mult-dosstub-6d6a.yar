rule TTP_XOR_MULT_DOSStub_6d6a {
  strings:
    $key_6d6a = { 39 02 [2] 4d 1a [2] 0a 18 [2] 4d 09 [2] 03 05 [2] 0f 0f [2] 18 04 [2] 03 4a [2] 3e }

  condition:
    any of them
}