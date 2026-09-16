rule TTP_XOR_MULT_DOSStub_022f {
  strings:
    $key_022f = { 56 47 [2] 22 5f [2] 65 5d [2] 22 4c [2] 6c 40 [2] 60 4a [2] 77 41 [2] 6c 0f [2] 51 }

  condition:
    any of them
}