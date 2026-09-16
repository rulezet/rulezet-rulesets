rule TTP_XOR_MULT_DOSStub_21fd {
  strings:
    $key_21fd = { 75 95 [2] 01 8d [2] 46 8f [2] 01 9e [2] 4f 92 [2] 43 98 [2] 54 93 [2] 4f dd [2] 72 }

  condition:
    any of them
}