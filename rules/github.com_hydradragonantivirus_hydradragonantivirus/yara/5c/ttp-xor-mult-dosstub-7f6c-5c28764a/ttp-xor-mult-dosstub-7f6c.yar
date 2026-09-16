rule TTP_XOR_MULT_DOSStub_7f6c {
  strings:
    $key_7f6c = { 2b 04 [2] 5f 1c [2] 18 1e [2] 5f 0f [2] 11 03 [2] 1d 09 [2] 0a 02 [2] 11 4c [2] 2c }

  condition:
    any of them
}