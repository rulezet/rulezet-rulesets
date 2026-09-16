rule TTP_XOR_MULT_DOSStub_1f2e {
  strings:
    $key_1f2e = { 4b 46 [2] 3f 5e [2] 78 5c [2] 3f 4d [2] 71 41 [2] 7d 4b [2] 6a 40 [2] 71 0e [2] 4c }

  condition:
    any of them
}