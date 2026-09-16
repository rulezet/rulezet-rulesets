rule TTP_XOR_MULT_DOSStub_596c {
  strings:
    $key_596c = { 0d 04 [2] 79 1c [2] 3e 1e [2] 79 0f [2] 37 03 [2] 3b 09 [2] 2c 02 [2] 37 4c [2] 0a }

  condition:
    any of them
}