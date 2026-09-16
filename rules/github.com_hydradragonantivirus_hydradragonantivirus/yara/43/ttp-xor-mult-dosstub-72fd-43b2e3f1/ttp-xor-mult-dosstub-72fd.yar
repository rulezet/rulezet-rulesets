rule TTP_XOR_MULT_DOSStub_72fd {
  strings:
    $key_72fd = { 26 95 [2] 52 8d [2] 15 8f [2] 52 9e [2] 1c 92 [2] 10 98 [2] 07 93 [2] 1c dd [2] 21 }

  condition:
    any of them
}