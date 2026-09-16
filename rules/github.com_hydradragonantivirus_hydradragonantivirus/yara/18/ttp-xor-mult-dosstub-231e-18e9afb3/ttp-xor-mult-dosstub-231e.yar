rule TTP_XOR_MULT_DOSStub_231e {
  strings:
    $key_231e = { 77 76 [2] 03 6e [2] 44 6c [2] 03 7d [2] 4d 71 [2] 41 7b [2] 56 70 [2] 4d 3e [2] 70 }

  condition:
    any of them
}