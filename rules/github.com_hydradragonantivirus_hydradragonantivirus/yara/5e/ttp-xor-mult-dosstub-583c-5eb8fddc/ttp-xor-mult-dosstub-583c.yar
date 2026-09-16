rule TTP_XOR_MULT_DOSStub_583c {
  strings:
    $key_583c = { 0c 54 [2] 78 4c [2] 3f 4e [2] 78 5f [2] 36 53 [2] 3a 59 [2] 2d 52 [2] 36 1c [2] 0b }

  condition:
    any of them
}