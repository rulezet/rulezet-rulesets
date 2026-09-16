rule TTP_XOR_MULT_DOSStub_fb33 {
  strings:
    $key_fb33 = { af 5b [2] db 43 [2] 9c 41 [2] db 50 [2] 95 5c [2] 99 56 [2] 8e 5d [2] 95 13 [2] a8 }

  condition:
    any of them
}