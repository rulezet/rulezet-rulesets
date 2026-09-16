rule TTP_XOR_MULT_DOSStub_526c {
  strings:
    $key_526c = { 06 04 [2] 72 1c [2] 35 1e [2] 72 0f [2] 3c 03 [2] 30 09 [2] 27 02 [2] 3c 4c [2] 01 }

  condition:
    any of them
}