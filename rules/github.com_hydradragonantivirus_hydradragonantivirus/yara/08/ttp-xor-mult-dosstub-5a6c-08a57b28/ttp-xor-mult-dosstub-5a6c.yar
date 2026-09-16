rule TTP_XOR_MULT_DOSStub_5a6c {
  strings:
    $key_5a6c = { 0e 04 [2] 7a 1c [2] 3d 1e [2] 7a 0f [2] 34 03 [2] 38 09 [2] 2f 02 [2] 34 4c [2] 09 }

  condition:
    any of them
}