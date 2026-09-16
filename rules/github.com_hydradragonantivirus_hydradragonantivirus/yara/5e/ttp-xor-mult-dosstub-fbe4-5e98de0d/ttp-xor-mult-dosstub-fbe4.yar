rule TTP_XOR_MULT_DOSStub_fbe4 {
  strings:
    $key_fbe4 = { af 8c [2] db 94 [2] 9c 96 [2] db 87 [2] 95 8b [2] 99 81 [2] 8e 8a [2] 95 c4 [2] a8 }

  condition:
    any of them
}