rule TTP_XOR_MULT_DOSStub_57fd {
  strings:
    $key_57fd = { 03 95 [2] 77 8d [2] 30 8f [2] 77 9e [2] 39 92 [2] 35 98 [2] 22 93 [2] 39 dd [2] 04 }

  condition:
    any of them
}