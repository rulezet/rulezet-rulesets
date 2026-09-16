rule TTP_XOR_MULT_DOSStub_0b6c {
  strings:
    $key_0b6c = { 5f 04 [2] 2b 1c [2] 6c 1e [2] 2b 0f [2] 65 03 [2] 69 09 [2] 7e 02 [2] 65 4c [2] 58 }

  condition:
    any of them
}