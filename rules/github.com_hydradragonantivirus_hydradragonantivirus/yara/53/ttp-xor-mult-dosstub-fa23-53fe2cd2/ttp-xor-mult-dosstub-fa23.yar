rule TTP_XOR_MULT_DOSStub_fa23 {
  strings:
    $key_fa23 = { ae 4b [2] da 53 [2] 9d 51 [2] da 40 [2] 94 4c [2] 98 46 [2] 8f 4d [2] 94 03 [2] a9 }

  condition:
    any of them
}