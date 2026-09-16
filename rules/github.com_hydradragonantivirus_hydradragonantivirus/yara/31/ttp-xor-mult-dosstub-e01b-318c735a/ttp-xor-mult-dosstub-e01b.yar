rule TTP_XOR_MULT_DOSStub_e01b {
  strings:
    $key_e01b = { b4 73 [2] c0 6b [2] 87 69 [2] c0 78 [2] 8e 74 [2] 82 7e [2] 95 75 [2] 8e 3b [2] b3 }

  condition:
    any of them
}