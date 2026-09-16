rule TTP_XOR_MULT_DOSStub_4d6c {
  strings:
    $key_4d6c = { 19 04 [2] 6d 1c [2] 2a 1e [2] 6d 0f [2] 23 03 [2] 2f 09 [2] 38 02 [2] 23 4c [2] 1e }

  condition:
    any of them
}