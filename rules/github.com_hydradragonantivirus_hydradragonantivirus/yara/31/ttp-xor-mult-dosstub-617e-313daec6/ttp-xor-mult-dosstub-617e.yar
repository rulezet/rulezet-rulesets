rule TTP_XOR_MULT_DOSStub_617e {
  strings:
    $key_617e = { 35 16 [2] 41 0e [2] 06 0c [2] 41 1d [2] 0f 11 [2] 03 1b [2] 14 10 [2] 0f 5e [2] 32 }

  condition:
    any of them
}