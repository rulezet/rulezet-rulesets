rule TTP_XOR_MULT_DOSStub_683e {
  strings:
    $key_683e = { 3c 56 [2] 48 4e [2] 0f 4c [2] 48 5d [2] 06 51 [2] 0a 5b [2] 1d 50 [2] 06 1e [2] 3b }

  condition:
    any of them
}