rule TTP_XOR_MULT_DOSStub_f418 {
  strings:
    $key_f418 = { a0 70 [2] d4 68 [2] 93 6a [2] d4 7b [2] 9a 77 [2] 96 7d [2] 81 76 [2] 9a 38 [2] a7 }

  condition:
    any of them
}