rule TTP_XOR_MULT_DOSStub_102f {
  strings:
    $key_102f = { 44 47 [2] 30 5f [2] 77 5d [2] 30 4c [2] 7e 40 [2] 72 4a [2] 65 41 [2] 7e 0f [2] 43 }

  condition:
    any of them
}