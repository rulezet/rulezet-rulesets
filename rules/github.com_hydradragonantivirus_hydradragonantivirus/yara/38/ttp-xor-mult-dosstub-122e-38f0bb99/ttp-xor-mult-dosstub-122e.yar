rule TTP_XOR_MULT_DOSStub_122e {
  strings:
    $key_122e = { 46 46 [2] 32 5e [2] 75 5c [2] 32 4d [2] 7c 41 [2] 70 4b [2] 67 40 [2] 7c 0e [2] 41 }

  condition:
    any of them
}