rule TTP_XOR_MULT_DOSStub_333e {
  strings:
    $key_333e = { 67 56 [2] 13 4e [2] 54 4c [2] 13 5d [2] 5d 51 [2] 51 5b [2] 46 50 [2] 5d 1e [2] 60 }

  condition:
    any of them
}