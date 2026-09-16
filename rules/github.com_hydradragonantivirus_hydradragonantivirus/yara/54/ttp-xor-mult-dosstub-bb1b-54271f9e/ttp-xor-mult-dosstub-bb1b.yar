rule TTP_XOR_MULT_DOSStub_bb1b {
  strings:
    $key_bb1b = { ef 73 [2] 9b 6b [2] dc 69 [2] 9b 78 [2] d5 74 [2] d9 7e [2] ce 75 [2] d5 3b [2] e8 }

  condition:
    any of them
}