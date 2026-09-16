rule TTP_XOR_MULT_DOSStub_01fd {
  strings:
    $key_01fd = { 55 95 [2] 21 8d [2] 66 8f [2] 21 9e [2] 6f 92 [2] 63 98 [2] 74 93 [2] 6f dd [2] 52 }

  condition:
    any of them
}