rule TTP_XOR_MULT_DOSStub_e00c {
  strings:
    $key_e00c = { b4 64 [2] c0 7c [2] 87 7e [2] c0 6f [2] 8e 63 [2] 82 69 [2] 95 62 [2] 8e 2c [2] b3 }

  condition:
    any of them
}