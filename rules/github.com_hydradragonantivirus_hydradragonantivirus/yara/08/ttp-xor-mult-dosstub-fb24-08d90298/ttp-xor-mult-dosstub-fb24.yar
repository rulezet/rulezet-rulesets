rule TTP_XOR_MULT_DOSStub_fb24 {
  strings:
    $key_fb24 = { af 4c [2] db 54 [2] 9c 56 [2] db 47 [2] 95 4b [2] 99 41 [2] 8e 4a [2] 95 04 [2] a8 }

  condition:
    any of them
}