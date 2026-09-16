rule TTP_XOR_MULT_DOSStub_51fd {
  strings:
    $key_51fd = { 05 95 [2] 71 8d [2] 36 8f [2] 71 9e [2] 3f 92 [2] 33 98 [2] 24 93 [2] 3f dd [2] 02 }

  condition:
    any of them
}