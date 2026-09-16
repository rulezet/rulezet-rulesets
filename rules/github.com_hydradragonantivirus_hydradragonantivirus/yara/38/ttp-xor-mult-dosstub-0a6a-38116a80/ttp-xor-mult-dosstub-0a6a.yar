rule TTP_XOR_MULT_DOSStub_0a6a {
  strings:
    $key_0a6a = { 5e 02 [2] 2a 1a [2] 6d 18 [2] 2a 09 [2] 64 05 [2] 68 0f [2] 7f 04 [2] 64 4a [2] 59 }

  condition:
    any of them
}