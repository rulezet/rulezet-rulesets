rule TTP_XOR_MULT_DOSStub_bb08 {
  strings:
    $key_bb08 = { ef 60 [2] 9b 78 [2] dc 7a [2] 9b 6b [2] d5 67 [2] d9 6d [2] ce 66 [2] d5 28 [2] e8 }

  condition:
    any of them
}