rule TTP_XOR_MULT_DOSStub_c025 {
  strings:
    $key_c025 = { 94 4d [2] e0 55 [2] a7 57 [2] e0 46 [2] ae 4a [2] a2 40 [2] b5 4b [2] ae 05 [2] 93 }

  condition:
    any of them
}