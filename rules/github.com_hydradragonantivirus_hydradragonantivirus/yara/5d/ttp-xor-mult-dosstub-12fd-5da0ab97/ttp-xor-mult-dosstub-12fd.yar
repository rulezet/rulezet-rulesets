rule TTP_XOR_MULT_DOSStub_12fd {
  strings:
    $key_12fd = { 46 95 [2] 32 8d [2] 75 8f [2] 32 9e [2] 7c 92 [2] 70 98 [2] 67 93 [2] 7c dd [2] 41 }

  condition:
    any of them
}