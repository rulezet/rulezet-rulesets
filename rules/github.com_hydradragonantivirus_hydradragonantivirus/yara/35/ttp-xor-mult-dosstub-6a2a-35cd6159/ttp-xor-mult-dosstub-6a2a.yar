rule TTP_XOR_MULT_DOSStub_6a2a {
  strings:
    $key_6a2a = { 3e 42 [2] 4a 5a [2] 0d 58 [2] 4a 49 [2] 04 45 [2] 08 4f [2] 1f 44 [2] 04 0a [2] 39 }

  condition:
    any of them
}