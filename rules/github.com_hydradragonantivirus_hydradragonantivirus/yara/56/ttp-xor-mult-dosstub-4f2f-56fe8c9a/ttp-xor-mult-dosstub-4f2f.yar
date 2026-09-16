rule TTP_XOR_MULT_DOSStub_4f2f {
  strings:
    $key_4f2f = { 1b 47 [2] 6f 5f [2] 28 5d [2] 6f 4c [2] 21 40 [2] 2d 4a [2] 3a 41 [2] 21 0f [2] 1c }

  condition:
    any of them
}