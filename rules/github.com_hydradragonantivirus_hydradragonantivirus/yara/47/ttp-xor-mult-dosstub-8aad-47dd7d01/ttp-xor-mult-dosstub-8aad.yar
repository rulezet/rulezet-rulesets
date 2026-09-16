rule TTP_XOR_MULT_DOSStub_8aad {
  strings:
    $key_8aad = { de c5 [2] aa dd [2] ed df [2] aa ce [2] e4 c2 [2] e8 c8 [2] ff c3 [2] e4 8d [2] d9 }

  condition:
    any of them
}