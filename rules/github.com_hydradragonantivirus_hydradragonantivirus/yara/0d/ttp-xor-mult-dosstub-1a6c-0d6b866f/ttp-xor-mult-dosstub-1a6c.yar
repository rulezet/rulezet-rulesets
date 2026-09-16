rule TTP_XOR_MULT_DOSStub_1a6c {
  strings:
    $key_1a6c = { 4e 04 [2] 3a 1c [2] 7d 1e [2] 3a 0f [2] 74 03 [2] 78 09 [2] 6f 02 [2] 74 4c [2] 49 }

  condition:
    any of them
}