rule TTP_XOR_MULT_DOSStub_fb29 {
  strings:
    $key_fb29 = { af 41 [2] db 59 [2] 9c 5b [2] db 4a [2] 95 46 [2] 99 4c [2] 8e 47 [2] 95 09 [2] a8 }

  condition:
    any of them
}