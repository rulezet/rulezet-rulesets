rule TTP_XOR_MULT_DOSStub_bbb8 {
  strings:
    $key_bbb8 = { ef d0 [2] 9b c8 [2] dc ca [2] 9b db [2] d5 d7 [2] d9 dd [2] ce d6 [2] d5 98 [2] e8 }

  condition:
    any of them
}