rule TTP_XOR_MULT_DOSStub_230e {
  strings:
    $key_230e = { 77 66 [2] 03 7e [2] 44 7c [2] 03 6d [2] 4d 61 [2] 41 6b [2] 56 60 [2] 4d 2e [2] 70 }

  condition:
    any of them
}