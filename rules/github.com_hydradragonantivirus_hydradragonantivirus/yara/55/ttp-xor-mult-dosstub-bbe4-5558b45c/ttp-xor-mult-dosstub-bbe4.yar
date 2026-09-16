rule TTP_XOR_MULT_DOSStub_bbe4 {
  strings:
    $key_bbe4 = { ef 8c [2] 9b 94 [2] dc 96 [2] 9b 87 [2] d5 8b [2] d9 81 [2] ce 8a [2] d5 c4 [2] e8 }

  condition:
    any of them
}