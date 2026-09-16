rule TTP_XOR_MULT_DOSStub_18fd {
  strings:
    $key_18fd = { 4c 95 [2] 38 8d [2] 7f 8f [2] 38 9e [2] 76 92 [2] 7a 98 [2] 6d 93 [2] 76 dd [2] 4b }

  condition:
    any of them
}