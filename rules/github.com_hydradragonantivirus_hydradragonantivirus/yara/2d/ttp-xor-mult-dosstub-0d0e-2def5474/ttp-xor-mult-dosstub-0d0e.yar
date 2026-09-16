rule TTP_XOR_MULT_DOSStub_0d0e {
  strings:
    $key_0d0e = { 59 66 [2] 2d 7e [2] 6a 7c [2] 2d 6d [2] 63 61 [2] 6f 6b [2] 78 60 [2] 63 2e [2] 5e }

  condition:
    any of them
}