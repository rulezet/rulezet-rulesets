rule TTP_XOR_MULT_DOSStub_1f3e {
  strings:
    $key_1f3e = { 4b 56 [2] 3f 4e [2] 78 4c [2] 3f 5d [2] 71 51 [2] 7d 5b [2] 6a 50 [2] 71 1e [2] 4c }

  condition:
    any of them
}