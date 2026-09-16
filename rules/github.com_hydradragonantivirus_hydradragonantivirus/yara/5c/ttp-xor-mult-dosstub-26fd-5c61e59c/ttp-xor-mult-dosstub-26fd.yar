rule TTP_XOR_MULT_DOSStub_26fd {
  strings:
    $key_26fd = { 72 95 [2] 06 8d [2] 41 8f [2] 06 9e [2] 48 92 [2] 44 98 [2] 53 93 [2] 48 dd [2] 75 }

  condition:
    any of them
}