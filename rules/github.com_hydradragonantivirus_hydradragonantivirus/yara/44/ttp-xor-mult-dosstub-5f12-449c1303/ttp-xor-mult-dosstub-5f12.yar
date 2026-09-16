rule TTP_XOR_MULT_DOSStub_5f12 {
  strings:
    $key_5f12 = { 0b 7a [2] 7f 62 [2] 38 60 [2] 7f 71 [2] 31 7d [2] 3d 77 [2] 2a 7c [2] 31 32 [2] 0c }

  condition:
    any of them
}