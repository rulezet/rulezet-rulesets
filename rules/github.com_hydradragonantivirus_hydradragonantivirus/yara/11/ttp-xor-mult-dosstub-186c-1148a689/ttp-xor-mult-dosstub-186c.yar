rule TTP_XOR_MULT_DOSStub_186c {
  strings:
    $key_186c = { 4c 04 [2] 38 1c [2] 7f 1e [2] 38 0f [2] 76 03 [2] 7a 09 [2] 6d 02 [2] 76 4c [2] 4b }

  condition:
    any of them
}