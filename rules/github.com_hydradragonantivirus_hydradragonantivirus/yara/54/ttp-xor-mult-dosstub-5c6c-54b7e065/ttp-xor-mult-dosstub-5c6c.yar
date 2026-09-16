rule TTP_XOR_MULT_DOSStub_5c6c {
  strings:
    $key_5c6c = { 08 04 [2] 7c 1c [2] 3b 1e [2] 7c 0f [2] 32 03 [2] 3e 09 [2] 29 02 [2] 32 4c [2] 0f }

  condition:
    any of them
}