rule TTP_XOR_MULT_DOSStub_581e {
  strings:
    $key_581e = { 0c 76 [2] 78 6e [2] 3f 6c [2] 78 7d [2] 36 71 [2] 3a 7b [2] 2d 70 [2] 36 3e [2] 0b }

  condition:
    any of them
}