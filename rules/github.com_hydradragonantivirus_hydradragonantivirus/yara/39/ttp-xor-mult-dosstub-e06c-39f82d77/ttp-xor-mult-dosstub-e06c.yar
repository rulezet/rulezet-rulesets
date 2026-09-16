rule TTP_XOR_MULT_DOSStub_e06c {
  strings:
    $key_e06c = { b4 04 [2] c0 1c [2] 87 1e [2] c0 0f [2] 8e 03 [2] 82 09 [2] 95 02 [2] 8e 4c [2] b3 }

  condition:
    any of them
}