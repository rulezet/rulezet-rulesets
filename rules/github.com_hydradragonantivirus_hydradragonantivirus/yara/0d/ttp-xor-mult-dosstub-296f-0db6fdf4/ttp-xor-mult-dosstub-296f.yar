rule TTP_XOR_MULT_DOSStub_296f {
  strings:
    $key_296f = { 7d 07 [2] 09 1f [2] 4e 1d [2] 09 0c [2] 47 00 [2] 4b 0a [2] 5c 01 [2] 47 4f [2] 7a }

  condition:
    any of them
}