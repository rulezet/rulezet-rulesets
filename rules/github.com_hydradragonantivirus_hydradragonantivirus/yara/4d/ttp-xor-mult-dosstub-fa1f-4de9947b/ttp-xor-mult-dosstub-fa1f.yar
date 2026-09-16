rule TTP_XOR_MULT_DOSStub_fa1f {
  strings:
    $key_fa1f = { ae 77 [2] da 6f [2] 9d 6d [2] da 7c [2] 94 70 [2] 98 7a [2] 8f 71 [2] 94 3f [2] a9 }

  condition:
    any of them
}