rule TTP_XOR_MULT_DOSStub_120e {
  strings:
    $key_120e = { 46 66 [2] 32 7e [2] 75 7c [2] 32 6d [2] 7c 61 [2] 70 6b [2] 67 60 [2] 7c 2e [2] 41 }

  condition:
    any of them
}