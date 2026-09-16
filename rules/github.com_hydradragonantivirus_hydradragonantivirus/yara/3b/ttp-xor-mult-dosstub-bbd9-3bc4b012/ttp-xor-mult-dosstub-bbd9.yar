rule TTP_XOR_MULT_DOSStub_bbd9 {
  strings:
    $key_bbd9 = { ef b1 [2] 9b a9 [2] dc ab [2] 9b ba [2] d5 b6 [2] d9 bc [2] ce b7 [2] d5 f9 [2] e8 }

  condition:
    any of them
}