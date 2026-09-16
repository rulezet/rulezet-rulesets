rule TTP_XOR_MULT_DOSStub_020e {
  strings:
    $key_020e = { 56 66 [2] 22 7e [2] 65 7c [2] 22 6d [2] 6c 61 [2] 60 6b [2] 77 60 [2] 6c 2e [2] 51 }

  condition:
    any of them
}