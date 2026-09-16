rule TTP_XOR_MULT_DOSStub_162e {
  strings:
    $key_162e = { 42 46 [2] 36 5e [2] 71 5c [2] 36 4d [2] 78 41 [2] 74 4b [2] 63 40 [2] 78 0e [2] 45 }

  condition:
    any of them
}