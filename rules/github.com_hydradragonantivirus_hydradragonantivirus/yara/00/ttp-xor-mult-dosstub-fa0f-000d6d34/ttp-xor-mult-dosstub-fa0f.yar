rule TTP_XOR_MULT_DOSStub_fa0f {
  strings:
    $key_fa0f = { ae 67 [2] da 7f [2] 9d 7d [2] da 6c [2] 94 60 [2] 98 6a [2] 8f 61 [2] 94 2f [2] a9 }

  condition:
    any of them
}