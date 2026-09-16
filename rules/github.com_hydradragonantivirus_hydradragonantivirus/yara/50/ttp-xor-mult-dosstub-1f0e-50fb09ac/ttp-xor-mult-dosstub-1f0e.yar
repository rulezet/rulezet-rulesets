rule TTP_XOR_MULT_DOSStub_1f0e {
  strings:
    $key_1f0e = { 4b 66 [2] 3f 7e [2] 78 7c [2] 3f 6d [2] 71 61 [2] 7d 6b [2] 6a 60 [2] 71 2e [2] 4c }

  condition:
    any of them
}