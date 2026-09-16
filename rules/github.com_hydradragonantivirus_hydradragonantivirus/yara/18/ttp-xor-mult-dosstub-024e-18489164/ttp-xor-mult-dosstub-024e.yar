rule TTP_XOR_MULT_DOSStub_024e {
  strings:
    $key_024e = { 56 26 [2] 22 3e [2] 65 3c [2] 22 2d [2] 6c 21 [2] 60 2b [2] 77 20 [2] 6c 6e [2] 51 }

  condition:
    any of them
}