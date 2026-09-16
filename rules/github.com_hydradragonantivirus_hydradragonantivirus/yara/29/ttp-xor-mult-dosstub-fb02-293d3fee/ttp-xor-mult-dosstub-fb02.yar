rule TTP_XOR_MULT_DOSStub_fb02 {
  strings:
    $key_fb02 = { af 6a [2] db 72 [2] 9c 70 [2] db 61 [2] 95 6d [2] 99 67 [2] 8e 6c [2] 95 22 [2] a8 }

  condition:
    any of them
}