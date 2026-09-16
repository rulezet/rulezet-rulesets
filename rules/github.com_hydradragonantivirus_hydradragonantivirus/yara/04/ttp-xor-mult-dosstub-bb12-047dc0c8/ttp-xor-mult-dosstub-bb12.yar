rule TTP_XOR_MULT_DOSStub_bb12 {
  strings:
    $key_bb12 = { ef 7a [2] 9b 62 [2] dc 60 [2] 9b 71 [2] d5 7d [2] d9 77 [2] ce 7c [2] d5 32 [2] e8 }

  condition:
    any of them
}