rule TTP_XOR_MULT_DOSStub_e00a {
  strings:
    $key_e00a = { b4 62 [2] c0 7a [2] 87 78 [2] c0 69 [2] 8e 65 [2] 82 6f [2] 95 64 [2] 8e 2a [2] b3 }

  condition:
    any of them
}