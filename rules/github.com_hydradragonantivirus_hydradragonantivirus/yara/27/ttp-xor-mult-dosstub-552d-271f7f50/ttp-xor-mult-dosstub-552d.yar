rule TTP_XOR_MULT_DOSStub_552d {
  strings:
    $key_552d = { 01 45 [2] 75 5d [2] 32 5f [2] 75 4e [2] 3b 42 [2] 37 48 [2] 20 43 [2] 3b 0d [2] 06 }

  condition:
    any of them
}