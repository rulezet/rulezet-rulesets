rule TTP_XOR_MULT_DOSStub_fb00 {
  strings:
    $key_fb00 = { af 68 [2] db 70 [2] 9c 72 [2] db 63 [2] 95 6f [2] 99 65 [2] 8e 6e [2] 95 20 [2] a8 }

  condition:
    any of them
}