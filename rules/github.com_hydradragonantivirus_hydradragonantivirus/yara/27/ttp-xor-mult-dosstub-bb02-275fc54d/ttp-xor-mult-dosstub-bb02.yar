rule TTP_XOR_MULT_DOSStub_bb02 {
  strings:
    $key_bb02 = { ef 6a [2] 9b 72 [2] dc 70 [2] 9b 61 [2] d5 6d [2] d9 67 [2] ce 6c [2] d5 22 [2] e8 }

  condition:
    any of them
}