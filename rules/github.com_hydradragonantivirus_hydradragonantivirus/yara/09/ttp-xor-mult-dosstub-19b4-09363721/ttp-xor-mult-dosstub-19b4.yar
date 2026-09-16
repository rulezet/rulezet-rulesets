rule TTP_XOR_MULT_DOSStub_19b4 {
  strings:
    $key_19b4 = { 4d dc [2] 39 c4 [2] 7e c6 [2] 39 d7 [2] 77 db [2] 7b d1 [2] 6c da [2] 77 94 [2] 4a }

  condition:
    any of them
}