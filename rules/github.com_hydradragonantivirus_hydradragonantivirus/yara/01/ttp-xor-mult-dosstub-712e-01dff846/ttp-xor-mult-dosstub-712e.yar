rule TTP_XOR_MULT_DOSStub_712e {
  strings:
    $key_712e = { 25 46 [2] 51 5e [2] 16 5c [2] 51 4d [2] 1f 41 [2] 13 4b [2] 04 40 [2] 1f 0e [2] 22 }

  condition:
    any of them
}