rule TTP_XOR_MULT_DOSStub_bb0e {
  strings:
    $key_bb0e = { ef 66 [2] 9b 7e [2] dc 7c [2] 9b 6d [2] d5 61 [2] d9 6b [2] ce 60 [2] d5 2e [2] e8 }

  condition:
    any of them
}