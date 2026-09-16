rule TTP_XOR_MULT_DOSStub_136e {
  strings:
    $key_136e = { 47 06 [2] 33 1e [2] 74 1c [2] 33 0d [2] 7d 01 [2] 71 0b [2] 66 00 [2] 7d 4e [2] 40 }

  condition:
    any of them
}