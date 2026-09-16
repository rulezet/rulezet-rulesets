rule TTP_XOR_MULT_DOSStub_282a {
  strings:
    $key_282a = { 7c 42 [2] 08 5a [2] 4f 58 [2] 08 49 [2] 46 45 [2] 4a 4f [2] 5d 44 [2] 46 0a [2] 7b }

  condition:
    any of them
}