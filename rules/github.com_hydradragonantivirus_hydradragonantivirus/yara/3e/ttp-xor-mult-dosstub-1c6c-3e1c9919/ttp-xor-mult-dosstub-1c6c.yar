rule TTP_XOR_MULT_DOSStub_1c6c {
  strings:
    $key_1c6c = { 48 04 [2] 3c 1c [2] 7b 1e [2] 3c 0f [2] 72 03 [2] 7e 09 [2] 69 02 [2] 72 4c [2] 4f }

  condition:
    any of them
}