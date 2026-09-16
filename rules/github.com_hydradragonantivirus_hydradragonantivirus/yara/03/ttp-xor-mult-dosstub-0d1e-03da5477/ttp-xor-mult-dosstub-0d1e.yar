rule TTP_XOR_MULT_DOSStub_0d1e {
  strings:
    $key_0d1e = { 59 76 [2] 2d 6e [2] 6a 6c [2] 2d 7d [2] 63 71 [2] 6f 7b [2] 78 70 [2] 63 3e [2] 5e }

  condition:
    any of them
}