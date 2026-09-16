rule TTP_XOR_MULT_DOSStub_344e {
  strings:
    $key_344e = { 60 26 [2] 14 3e [2] 53 3c [2] 14 2d [2] 5a 21 [2] 56 2b [2] 41 20 [2] 5a 6e [2] 67 }

  condition:
    any of them
}