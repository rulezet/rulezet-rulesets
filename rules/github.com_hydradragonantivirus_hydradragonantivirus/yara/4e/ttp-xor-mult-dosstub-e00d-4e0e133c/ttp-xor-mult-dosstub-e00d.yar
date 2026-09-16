rule TTP_XOR_MULT_DOSStub_e00d {
  strings:
    $key_e00d = { b4 65 [2] c0 7d [2] 87 7f [2] c0 6e [2] 8e 62 [2] 82 68 [2] 95 63 [2] 8e 2d [2] b3 }

  condition:
    any of them
}