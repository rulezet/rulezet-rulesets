rule TTP_XOR_MULT_DOSStub_e0fc {
  strings:
    $key_e0fc = { b4 94 [2] c0 8c [2] 87 8e [2] c0 9f [2] 8e 93 [2] 82 99 [2] 95 92 [2] 8e dc [2] b3 }

  condition:
    any of them
}