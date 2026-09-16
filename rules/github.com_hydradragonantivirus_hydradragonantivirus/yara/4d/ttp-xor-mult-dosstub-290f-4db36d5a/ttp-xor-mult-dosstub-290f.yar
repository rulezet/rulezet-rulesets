rule TTP_XOR_MULT_DOSStub_290f {
  strings:
    $key_290f = { 7d 67 [2] 09 7f [2] 4e 7d [2] 09 6c [2] 47 60 [2] 4b 6a [2] 5c 61 [2] 47 2f [2] 7a }

  condition:
    any of them
}