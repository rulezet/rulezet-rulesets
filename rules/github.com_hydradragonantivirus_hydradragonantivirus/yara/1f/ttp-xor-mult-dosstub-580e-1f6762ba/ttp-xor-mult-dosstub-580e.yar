rule TTP_XOR_MULT_DOSStub_580e {
  strings:
    $key_580e = { 0c 66 [2] 78 7e [2] 3f 7c [2] 78 6d [2] 36 61 [2] 3a 6b [2] 2d 60 [2] 36 2e [2] 0b }

  condition:
    any of them
}