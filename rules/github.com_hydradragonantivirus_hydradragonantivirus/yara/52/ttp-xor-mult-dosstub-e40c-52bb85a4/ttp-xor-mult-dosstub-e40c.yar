rule TTP_XOR_MULT_DOSStub_e40c {
  strings:
    $key_e40c = { b0 64 [2] c4 7c [2] 83 7e [2] c4 6f [2] 8a 63 [2] 86 69 [2] 91 62 [2] 8a 2c [2] b7 }

  condition:
    any of them
}