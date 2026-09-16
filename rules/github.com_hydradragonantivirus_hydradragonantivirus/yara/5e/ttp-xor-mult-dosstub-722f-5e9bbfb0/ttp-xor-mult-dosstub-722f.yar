rule TTP_XOR_MULT_DOSStub_722f {
  strings:
    $key_722f = { 26 47 [2] 52 5f [2] 15 5d [2] 52 4c [2] 1c 40 [2] 10 4a [2] 07 41 [2] 1c 0f [2] 21 }

  condition:
    any of them
}