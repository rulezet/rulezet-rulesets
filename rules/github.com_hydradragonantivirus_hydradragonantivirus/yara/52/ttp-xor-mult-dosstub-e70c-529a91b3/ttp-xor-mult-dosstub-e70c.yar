rule TTP_XOR_MULT_DOSStub_e70c {
  strings:
    $key_e70c = { b3 64 [2] c7 7c [2] 80 7e [2] c7 6f [2] 89 63 [2] 85 69 [2] 92 62 [2] 89 2c [2] b4 }

  condition:
    any of them
}