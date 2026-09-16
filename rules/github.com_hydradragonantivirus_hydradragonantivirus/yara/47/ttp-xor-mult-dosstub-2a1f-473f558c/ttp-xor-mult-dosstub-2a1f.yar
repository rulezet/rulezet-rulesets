rule TTP_XOR_MULT_DOSStub_2a1f {
  strings:
    $key_2a1f = { 7e 77 [2] 0a 6f [2] 4d 6d [2] 0a 7c [2] 44 70 [2] 48 7a [2] 5f 71 [2] 44 3f [2] 79 }

  condition:
    any of them
}