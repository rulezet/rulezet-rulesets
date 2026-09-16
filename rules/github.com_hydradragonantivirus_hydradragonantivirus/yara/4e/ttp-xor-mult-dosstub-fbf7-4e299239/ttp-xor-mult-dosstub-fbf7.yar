rule TTP_XOR_MULT_DOSStub_fbf7 {
  strings:
    $key_fbf7 = { af 9f [2] db 87 [2] 9c 85 [2] db 94 [2] 95 98 [2] 99 92 [2] 8e 99 [2] 95 d7 [2] a8 }

  condition:
    any of them
}