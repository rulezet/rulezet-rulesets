rule TTP_XOR_MULT_DOSStub_173f {
  strings:
    $key_173f = { 43 57 [2] 37 4f [2] 70 4d [2] 37 5c [2] 79 50 [2] 75 5a [2] 62 51 [2] 79 1f [2] 44 }

  condition:
    any of them
}