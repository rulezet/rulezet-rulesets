rule TTP_XOR_MULT_DOSStub_3f12 {
  strings:
    $key_3f12 = { 6b 7a [2] 1f 62 [2] 58 60 [2] 1f 71 [2] 51 7d [2] 5d 77 [2] 4a 7c [2] 51 32 [2] 6c }

  condition:
    any of them
}