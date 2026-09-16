rule TTP_XOR_MULT_DOSStub_362e {
  strings:
    $key_362e = { 62 46 [2] 16 5e [2] 51 5c [2] 16 4d [2] 58 41 [2] 54 4b [2] 43 40 [2] 58 0e [2] 65 }

  condition:
    any of them
}