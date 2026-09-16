rule TTP_XOR_MULT_DOSStub_2597 {
  strings:
    $key_2597 = { 71 ff [2] 05 e7 [2] 42 e5 [2] 05 f4 [2] 4b f8 [2] 47 f2 [2] 50 f9 [2] 4b b7 [2] 76 }

  condition:
    any of them
}