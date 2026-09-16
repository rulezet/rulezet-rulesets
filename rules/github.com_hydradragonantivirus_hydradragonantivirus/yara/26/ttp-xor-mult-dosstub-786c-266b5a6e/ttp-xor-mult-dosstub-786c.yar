rule TTP_XOR_MULT_DOSStub_786c {
  strings:
    $key_786c = { 2c 04 [2] 58 1c [2] 1f 1e [2] 58 0f [2] 16 03 [2] 1a 09 [2] 0d 02 [2] 16 4c [2] 2b }

  condition:
    any of them
}