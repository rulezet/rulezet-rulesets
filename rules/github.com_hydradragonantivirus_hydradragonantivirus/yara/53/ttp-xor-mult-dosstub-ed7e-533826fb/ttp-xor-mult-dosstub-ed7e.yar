rule TTP_XOR_MULT_DOSStub_ed7e {
  strings:
    $key_ed7e = { b9 16 [2] cd 0e [2] 8a 0c [2] cd 1d [2] 83 11 [2] 8f 1b [2] 98 10 [2] 83 5e [2] be }

  condition:
    any of them
}