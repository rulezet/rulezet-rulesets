rule TTP_XOR_MULT_DOSStub_38fd {
  strings:
    $key_38fd = { 6c 95 [2] 18 8d [2] 5f 8f [2] 18 9e [2] 56 92 [2] 5a 98 [2] 4d 93 [2] 56 dd [2] 6b }

  condition:
    any of them
}