rule TTP_XOR_MULT_DOSStub_fb77 {
  strings:
    $key_fb77 = { af 1f [2] db 07 [2] 9c 05 [2] db 14 [2] 95 18 [2] 99 12 [2] 8e 19 [2] 95 57 [2] a8 }

  condition:
    any of them
}