rule TTP_XOR_MULT_DOSStub_3f0e {
  strings:
    $key_3f0e = { 6b 66 [2] 1f 7e [2] 58 7c [2] 1f 6d [2] 51 61 [2] 5d 6b [2] 4a 60 [2] 51 2e [2] 6c }

  condition:
    any of them
}