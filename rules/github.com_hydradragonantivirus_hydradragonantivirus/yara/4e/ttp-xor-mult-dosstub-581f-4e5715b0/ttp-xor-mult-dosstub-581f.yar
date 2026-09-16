rule TTP_XOR_MULT_DOSStub_581f {
  strings:
    $key_581f = { 0c 77 [2] 78 6f [2] 3f 6d [2] 78 7c [2] 36 70 [2] 3a 7a [2] 2d 71 [2] 36 3f [2] 0b }

  condition:
    any of them
}