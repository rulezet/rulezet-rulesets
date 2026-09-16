rule TTP_XOR_MULT_DOSStub_05fd {
  strings:
    $key_05fd = { 51 95 [2] 25 8d [2] 62 8f [2] 25 9e [2] 6b 92 [2] 67 98 [2] 70 93 [2] 6b dd [2] 56 }

  condition:
    any of them
}