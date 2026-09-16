rule TTP_XOR_MULT_DOSStub_086c {
  strings:
    $key_086c = { 5c 04 [2] 28 1c [2] 6f 1e [2] 28 0f [2] 66 03 [2] 6a 09 [2] 7d 02 [2] 66 4c [2] 5b }

  condition:
    any of them
}