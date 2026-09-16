rule TTP_XOR_MULT_DOSStub_182e {
  strings:
    $key_182e = { 4c 46 [2] 38 5e [2] 7f 5c [2] 38 4d [2] 76 41 [2] 7a 4b [2] 6d 40 [2] 76 0e [2] 4b }

  condition:
    any of them
}