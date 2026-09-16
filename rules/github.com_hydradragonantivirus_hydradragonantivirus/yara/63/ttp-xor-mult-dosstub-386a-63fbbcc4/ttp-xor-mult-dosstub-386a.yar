rule TTP_XOR_MULT_DOSStub_386a {
  strings:
    $key_386a = { 6c 02 [2] 18 1a [2] 5f 18 [2] 18 09 [2] 56 05 [2] 5a 0f [2] 4d 04 [2] 56 4a [2] 6b }

  condition:
    any of them
}