rule TTP_XOR_MULT_DOSStub_524c {
  strings:
    $key_524c = { 06 24 [2] 72 3c [2] 35 3e [2] 72 2f [2] 3c 23 [2] 30 29 [2] 27 22 [2] 3c 6c [2] 01 }

  condition:
    any of them
}