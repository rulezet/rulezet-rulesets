rule TTP_XOR_MULT_DOSStub_fa2e {
  strings:
    $key_fa2e = { ae 46 [2] da 5e [2] 9d 5c [2] da 4d [2] 94 41 [2] 98 4b [2] 8f 40 [2] 94 0e [2] a9 }

  condition:
    any of them
}