rule TTP_XOR_MULT_DOSStub_601e {
  strings:
    $key_601e = { 34 76 [2] 40 6e [2] 07 6c [2] 40 7d [2] 0e 71 [2] 02 7b [2] 15 70 [2] 0e 3e [2] 33 }

  condition:
    any of them
}