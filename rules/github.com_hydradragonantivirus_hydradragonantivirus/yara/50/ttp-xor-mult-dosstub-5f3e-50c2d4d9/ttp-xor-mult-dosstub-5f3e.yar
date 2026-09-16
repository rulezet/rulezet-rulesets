rule TTP_XOR_MULT_DOSStub_5f3e {
  strings:
    $key_5f3e = { 0b 56 [2] 7f 4e [2] 38 4c [2] 7f 5d [2] 31 51 [2] 3d 5b [2] 2a 50 [2] 31 1e [2] 0c }

  condition:
    any of them
}