rule TTP_XOR_MULT_DOSStub_036c {
  strings:
    $key_036c = { 57 04 [2] 23 1c [2] 64 1e [2] 23 0f [2] 6d 03 [2] 61 09 [2] 76 02 [2] 6d 4c [2] 50 }

  condition:
    any of them
}