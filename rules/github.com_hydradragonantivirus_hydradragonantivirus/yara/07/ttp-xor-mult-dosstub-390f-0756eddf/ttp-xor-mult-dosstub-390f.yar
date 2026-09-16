rule TTP_XOR_MULT_DOSStub_390f {
  strings:
    $key_390f = { 6d 67 [2] 19 7f [2] 5e 7d [2] 19 6c [2] 57 60 [2] 5b 6a [2] 4c 61 [2] 57 2f [2] 6a }

  condition:
    any of them
}