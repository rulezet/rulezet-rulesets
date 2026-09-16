rule TTP_XOR_MULT_DOSStub_e56c {
  strings:
    $key_e56c = { b1 04 [2] c5 1c [2] 82 1e [2] c5 0f [2] 8b 03 [2] 87 09 [2] 90 02 [2] 8b 4c [2] b6 }

  condition:
    any of them
}