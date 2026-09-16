rule TTP_XOR_MULT_DOSStub_5f0e {
  strings:
    $key_5f0e = { 0b 66 [2] 7f 7e [2] 38 7c [2] 7f 6d [2] 31 61 [2] 3d 6b [2] 2a 60 [2] 31 2e [2] 0c }

  condition:
    any of them
}