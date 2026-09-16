rule TTP_XOR_MULT_DOSStub_bb3e {
  strings:
    $key_bb3e = { ef 56 [2] 9b 4e [2] dc 4c [2] 9b 5d [2] d5 51 [2] d9 5b [2] ce 50 [2] d5 1e [2] e8 }

  condition:
    any of them
}