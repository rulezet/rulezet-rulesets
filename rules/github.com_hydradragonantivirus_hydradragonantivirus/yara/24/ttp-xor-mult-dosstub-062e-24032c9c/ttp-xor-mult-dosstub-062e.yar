rule TTP_XOR_MULT_DOSStub_062e {
  strings:
    $key_062e = { 52 46 [2] 26 5e [2] 61 5c [2] 26 4d [2] 68 41 [2] 64 4b [2] 73 40 [2] 68 0e [2] 55 }

  condition:
    any of them
}