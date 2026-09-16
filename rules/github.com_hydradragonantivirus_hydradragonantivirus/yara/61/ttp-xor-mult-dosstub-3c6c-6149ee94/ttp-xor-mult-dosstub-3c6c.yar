rule TTP_XOR_MULT_DOSStub_3c6c {
  strings:
    $key_3c6c = { 68 04 [2] 1c 1c [2] 5b 1e [2] 1c 0f [2] 52 03 [2] 5e 09 [2] 49 02 [2] 52 4c [2] 6f }

  condition:
    any of them
}