rule TTP_XOR_MULT_DOSStub_c0fc {
  strings:
    $key_c0fc = { 94 94 [2] e0 8c [2] a7 8e [2] e0 9f [2] ae 93 [2] a2 99 [2] b5 92 [2] ae dc [2] 93 }

  condition:
    any of them
}