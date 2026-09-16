rule TTP_XOR_MULT_DOSStub_664e {
  strings:
    $key_664e = { 32 26 [2] 46 3e [2] 01 3c [2] 46 2d [2] 08 21 [2] 04 2b [2] 13 20 [2] 08 6e [2] 35 }

  condition:
    any of them
}