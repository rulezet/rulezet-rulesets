rule TTP_XOR_MULT_DOSStub_fb39 {
  strings:
    $key_fb39 = { af 51 [2] db 49 [2] 9c 4b [2] db 5a [2] 95 56 [2] 99 5c [2] 8e 57 [2] 95 19 [2] a8 }

  condition:
    any of them
}