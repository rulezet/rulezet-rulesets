rule TTP_XOR_MULT_DOSStub_3b55 {
  strings:
    $key_3b55 = { 6f 3d [2] 1b 25 [2] 5c 27 [2] 1b 36 [2] 55 3a [2] 59 30 [2] 4e 3b [2] 55 75 [2] 68 }

  condition:
    any of them
}