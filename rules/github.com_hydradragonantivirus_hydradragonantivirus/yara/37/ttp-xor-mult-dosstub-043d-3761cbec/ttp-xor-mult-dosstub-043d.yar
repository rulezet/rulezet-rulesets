rule TTP_XOR_MULT_DOSStub_043d {
  strings:
    $key_043d = { 50 55 [2] 24 4d [2] 63 4f [2] 24 5e [2] 6a 52 [2] 66 58 [2] 71 53 [2] 6a 1d [2] 57 }

  condition:
    any of them
}