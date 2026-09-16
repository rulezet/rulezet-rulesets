rule TTP_XOR_MULT_DOSStub_006e {
  strings:
    $key_006e = { 54 06 [2] 20 1e [2] 67 1c [2] 20 0d [2] 6e 01 [2] 62 0b [2] 75 00 [2] 6e 4e [2] 53 }

  condition:
    any of them
}