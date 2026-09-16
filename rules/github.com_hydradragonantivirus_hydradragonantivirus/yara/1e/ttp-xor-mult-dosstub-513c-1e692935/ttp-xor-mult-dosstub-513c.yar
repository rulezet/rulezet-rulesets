rule TTP_XOR_MULT_DOSStub_513c {
  strings:
    $key_513c = { 05 54 [2] 71 4c [2] 36 4e [2] 71 5f [2] 3f 53 [2] 33 59 [2] 24 52 [2] 3f 1c [2] 02 }

  condition:
    any of them
}