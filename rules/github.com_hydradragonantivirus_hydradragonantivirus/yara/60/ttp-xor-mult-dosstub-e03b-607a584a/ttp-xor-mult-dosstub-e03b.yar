rule TTP_XOR_MULT_DOSStub_e03b {
  strings:
    $key_e03b = { b4 53 [2] c0 4b [2] 87 49 [2] c0 58 [2] 8e 54 [2] 82 5e [2] 95 55 [2] 8e 1b [2] b3 }

  condition:
    any of them
}