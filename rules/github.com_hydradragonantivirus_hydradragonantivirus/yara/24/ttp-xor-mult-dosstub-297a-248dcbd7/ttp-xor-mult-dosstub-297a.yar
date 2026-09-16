rule TTP_XOR_MULT_DOSStub_297a {
  strings:
    $key_297a = { 7d 12 [2] 09 0a [2] 4e 08 [2] 09 19 [2] 47 15 [2] 4b 1f [2] 5c 14 [2] 47 5a [2] 7a }

  condition:
    any of them
}