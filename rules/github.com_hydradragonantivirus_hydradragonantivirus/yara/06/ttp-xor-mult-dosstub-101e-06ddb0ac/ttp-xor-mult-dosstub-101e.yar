rule TTP_XOR_MULT_DOSStub_101e {
  strings:
    $key_101e = { 44 76 [2] 30 6e [2] 77 6c [2] 30 7d [2] 7e 71 [2] 72 7b [2] 65 70 [2] 7e 3e [2] 43 }

  condition:
    any of them
}