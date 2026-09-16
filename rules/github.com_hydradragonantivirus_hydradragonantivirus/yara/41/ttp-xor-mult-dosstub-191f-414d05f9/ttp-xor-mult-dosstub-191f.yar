rule TTP_XOR_MULT_DOSStub_191f {
  strings:
    $key_191f = { 4d 77 [2] 39 6f [2] 7e 6d [2] 39 7c [2] 77 70 [2] 7b 7a [2] 6c 71 [2] 77 3f [2] 4a }

  condition:
    any of them
}