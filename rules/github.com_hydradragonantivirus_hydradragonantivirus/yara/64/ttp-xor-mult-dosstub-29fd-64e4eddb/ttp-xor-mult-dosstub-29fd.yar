rule TTP_XOR_MULT_DOSStub_29fd {
  strings:
    $key_29fd = { 7d 95 [2] 09 8d [2] 4e 8f [2] 09 9e [2] 47 92 [2] 4b 98 [2] 5c 93 [2] 47 dd [2] 7a }

  condition:
    any of them
}