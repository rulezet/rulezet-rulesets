rule TTP_XOR_MULT_DOSStub_bb04 {
  strings:
    $key_bb04 = { ef 6c [2] 9b 74 [2] dc 76 [2] 9b 67 [2] d5 6b [2] d9 61 [2] ce 6a [2] d5 24 [2] e8 }

  condition:
    any of them
}