rule TTP_XOR_MULT_DOSStub_2b81 {
  strings:
    $key_2b81 = { 7f e9 [2] 0b f1 [2] 4c f3 [2] 0b e2 [2] 45 ee [2] 49 e4 [2] 5e ef [2] 45 a1 [2] 78 }

  condition:
    any of them
}