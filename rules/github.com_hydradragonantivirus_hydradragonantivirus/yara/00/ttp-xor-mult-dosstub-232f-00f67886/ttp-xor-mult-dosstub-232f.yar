rule TTP_XOR_MULT_DOSStub_232f {
  strings:
    $key_232f = { 77 47 [2] 03 5f [2] 44 5d [2] 03 4c [2] 4d 40 [2] 41 4a [2] 56 41 [2] 4d 0f [2] 70 }

  condition:
    any of them
}