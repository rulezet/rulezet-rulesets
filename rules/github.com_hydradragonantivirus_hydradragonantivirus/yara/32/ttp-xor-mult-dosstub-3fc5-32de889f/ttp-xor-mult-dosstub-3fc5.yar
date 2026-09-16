rule TTP_XOR_MULT_DOSStub_3fc5 {
  strings:
    $key_3fc5 = { 6b ad [2] 1f b5 [2] 58 b7 [2] 1f a6 [2] 51 aa [2] 5d a0 [2] 4a ab [2] 51 e5 [2] 6c }

  condition:
    any of them
}