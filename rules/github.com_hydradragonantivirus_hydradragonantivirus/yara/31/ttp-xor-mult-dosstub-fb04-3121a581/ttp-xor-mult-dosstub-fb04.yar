rule TTP_XOR_MULT_DOSStub_fb04 {
  strings:
    $key_fb04 = { af 6c [2] db 74 [2] 9c 76 [2] db 67 [2] 95 6b [2] 99 61 [2] 8e 6a [2] 95 24 [2] a8 }

  condition:
    any of them
}