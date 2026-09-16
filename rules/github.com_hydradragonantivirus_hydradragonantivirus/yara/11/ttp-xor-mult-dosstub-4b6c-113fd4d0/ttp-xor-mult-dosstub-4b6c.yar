rule TTP_XOR_MULT_DOSStub_4b6c {
  strings:
    $key_4b6c = { 1f 04 [2] 6b 1c [2] 2c 1e [2] 6b 0f [2] 25 03 [2] 29 09 [2] 3e 02 [2] 25 4c [2] 18 }

  condition:
    any of them
}