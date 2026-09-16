rule TTP_XOR_MULT_DOSStub_552e {
  strings:
    $key_552e = { 01 46 [2] 75 5e [2] 32 5c [2] 75 4d [2] 3b 41 [2] 37 4b [2] 20 40 [2] 3b 0e [2] 06 }

  condition:
    any of them
}