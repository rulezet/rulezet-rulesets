rule TTP_XOR_MULT_DOSStub_2fb4 {
  strings:
    $key_2fb4 = { 7b dc [2] 0f c4 [2] 48 c6 [2] 0f d7 [2] 41 db [2] 4d d1 [2] 5a da [2] 41 94 [2] 7c }

  condition:
    any of them
}