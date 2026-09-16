rule TTP_XOR_MULT_DOSStub_fa6c {
  strings:
    $key_fa6c = { ae 04 [2] da 1c [2] 9d 1e [2] da 0f [2] 94 03 [2] 98 09 [2] 8f 02 [2] 94 4c [2] a9 }

  condition:
    any of them
}