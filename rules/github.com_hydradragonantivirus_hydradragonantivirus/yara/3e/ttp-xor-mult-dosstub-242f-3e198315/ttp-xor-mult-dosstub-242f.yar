rule TTP_XOR_MULT_DOSStub_242f {
  strings:
    $key_242f = { 70 47 [2] 04 5f [2] 43 5d [2] 04 4c [2] 4a 40 [2] 46 4a [2] 51 41 [2] 4a 0f [2] 77 }

  condition:
    any of them
}