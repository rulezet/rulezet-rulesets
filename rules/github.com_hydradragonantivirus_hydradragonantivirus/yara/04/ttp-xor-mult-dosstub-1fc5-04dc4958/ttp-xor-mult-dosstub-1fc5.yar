rule TTP_XOR_MULT_DOSStub_1fc5 {
  strings:
    $key_1fc5 = { 4b ad [2] 3f b5 [2] 78 b7 [2] 3f a6 [2] 71 aa [2] 7d a0 [2] 6a ab [2] 71 e5 [2] 4c }

  condition:
    any of them
}