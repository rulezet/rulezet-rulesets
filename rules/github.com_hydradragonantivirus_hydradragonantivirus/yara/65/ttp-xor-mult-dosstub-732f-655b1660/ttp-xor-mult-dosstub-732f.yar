rule TTP_XOR_MULT_DOSStub_732f {
  strings:
    $key_732f = { 27 47 [2] 53 5f [2] 14 5d [2] 53 4c [2] 1d 40 [2] 11 4a [2] 06 41 [2] 1d 0f [2] 20 }

  condition:
    any of them
}