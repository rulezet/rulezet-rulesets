rule TTP_XOR_MULT_DOSStub_676c {
  strings:
    $key_676c = { 33 04 [2] 47 1c [2] 00 1e [2] 47 0f [2] 09 03 [2] 05 09 [2] 12 02 [2] 09 4c [2] 34 }

  condition:
    any of them
}