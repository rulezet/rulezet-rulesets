rule TTP_XOR_MULT_DOSStub_f0fc {
  strings:
    $key_f0fc = { a4 94 [2] d0 8c [2] 97 8e [2] d0 9f [2] 9e 93 [2] 92 99 [2] 85 92 [2] 9e dc [2] a3 }

  condition:
    any of them
}