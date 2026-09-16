rule TTP_XOR_MULT_DOSStub_2a6c {
  strings:
    $key_2a6c = { 7e 04 [2] 0a 1c [2] 4d 1e [2] 0a 0f [2] 44 03 [2] 48 09 [2] 5f 02 [2] 44 4c [2] 79 }

  condition:
    any of them
}