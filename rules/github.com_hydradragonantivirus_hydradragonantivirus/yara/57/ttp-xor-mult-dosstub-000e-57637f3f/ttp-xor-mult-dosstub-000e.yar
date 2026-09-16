rule TTP_XOR_MULT_DOSStub_000e {
  strings:
    $key_000e = { 54 66 [2] 20 7e [2] 67 7c [2] 20 6d [2] 6e 61 [2] 62 6b [2] 75 60 [2] 6e 2e [2] 53 }

  condition:
    any of them
}