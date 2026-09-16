rule TTP_XOR_MULT_DOSStub_fa1e {
  strings:
    $key_fa1e = { ae 76 [2] da 6e [2] 9d 6c [2] da 7d [2] 94 71 [2] 98 7b [2] 8f 70 [2] 94 3e [2] a9 }

  condition:
    any of them
}