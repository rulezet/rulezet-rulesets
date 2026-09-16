rule TTP_XOR_MULT_DOSStub_1b6c {
  strings:
    $key_1b6c = { 4f 04 [2] 3b 1c [2] 7c 1e [2] 3b 0f [2] 75 03 [2] 79 09 [2] 6e 02 [2] 75 4c [2] 48 }

  condition:
    any of them
}