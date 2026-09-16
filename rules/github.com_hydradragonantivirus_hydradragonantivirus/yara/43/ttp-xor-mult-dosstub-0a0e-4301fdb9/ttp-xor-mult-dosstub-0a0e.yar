rule TTP_XOR_MULT_DOSStub_0a0e {
  strings:
    $key_0a0e = { 5e 66 [2] 2a 7e [2] 6d 7c [2] 2a 6d [2] 64 61 [2] 68 6b [2] 7f 60 [2] 64 2e [2] 59 }

  condition:
    any of them
}