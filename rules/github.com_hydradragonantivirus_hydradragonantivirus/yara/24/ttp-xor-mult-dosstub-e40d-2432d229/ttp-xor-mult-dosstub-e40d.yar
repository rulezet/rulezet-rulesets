rule TTP_XOR_MULT_DOSStub_e40d {
  strings:
    $key_e40d = { b0 65 [2] c4 7d [2] 83 7f [2] c4 6e [2] 8a 62 [2] 86 68 [2] 91 63 [2] 8a 2d [2] b7 }

  condition:
    any of them
}