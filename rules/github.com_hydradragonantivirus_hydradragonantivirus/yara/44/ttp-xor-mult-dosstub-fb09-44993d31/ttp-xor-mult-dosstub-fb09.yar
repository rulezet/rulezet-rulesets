rule TTP_XOR_MULT_DOSStub_fb09 {
  strings:
    $key_fb09 = { af 61 [2] db 79 [2] 9c 7b [2] db 6a [2] 95 66 [2] 99 6c [2] 8e 67 [2] 95 29 [2] a8 }

  condition:
    any of them
}