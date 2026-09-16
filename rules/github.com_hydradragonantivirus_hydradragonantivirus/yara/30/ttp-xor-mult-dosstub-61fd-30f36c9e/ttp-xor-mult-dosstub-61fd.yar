rule TTP_XOR_MULT_DOSStub_61fd {
  strings:
    $key_61fd = { 35 95 [2] 41 8d [2] 06 8f [2] 41 9e [2] 0f 92 [2] 03 98 [2] 14 93 [2] 0f dd [2] 32 }

  condition:
    any of them
}