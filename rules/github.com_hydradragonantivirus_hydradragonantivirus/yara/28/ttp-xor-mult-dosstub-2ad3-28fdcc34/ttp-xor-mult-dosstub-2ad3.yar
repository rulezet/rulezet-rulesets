rule TTP_XOR_MULT_DOSStub_2ad3 {
  strings:
    $key_2ad3 = { 7e bb [2] 0a a3 [2] 4d a1 [2] 0a b0 [2] 44 bc [2] 48 b6 [2] 5f bd [2] 44 f3 [2] 79 }

  condition:
    any of them
}