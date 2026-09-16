rule TTP_XOR_MULT_DOSStub_126e {
  strings:
    $key_126e = { 46 06 [2] 32 1e [2] 75 1c [2] 32 0d [2] 7c 01 [2] 70 0b [2] 67 00 [2] 7c 4e [2] 41 }

  condition:
    any of them
}