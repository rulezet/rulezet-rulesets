rule TTP_XOR_MULT_DOSStub_e09b {
  strings:
    $key_e09b = { b4 f3 [2] c0 eb [2] 87 e9 [2] c0 f8 [2] 8e f4 [2] 82 fe [2] 95 f5 [2] 8e bb [2] b3 }

  condition:
    any of them
}