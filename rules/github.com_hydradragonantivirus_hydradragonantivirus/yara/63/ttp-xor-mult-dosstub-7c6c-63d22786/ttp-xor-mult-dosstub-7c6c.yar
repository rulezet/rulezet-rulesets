rule TTP_XOR_MULT_DOSStub_7c6c {
  strings:
    $key_7c6c = { 28 04 [2] 5c 1c [2] 1b 1e [2] 5c 0f [2] 12 03 [2] 1e 09 [2] 09 02 [2] 12 4c [2] 2f }

  condition:
    any of them
}