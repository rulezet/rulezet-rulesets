rule TTP_XOR_MULT_DOSStub_02fd {
  strings:
    $key_02fd = { 56 95 [2] 22 8d [2] 65 8f [2] 22 9e [2] 6c 92 [2] 60 98 [2] 77 93 [2] 6c dd [2] 51 }

  condition:
    any of them
}