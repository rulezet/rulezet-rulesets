rule TTP_XOR_MULT_DOSStub_41fd {
  strings:
    $key_41fd = { 15 95 [2] 61 8d [2] 26 8f [2] 61 9e [2] 2f 92 [2] 23 98 [2] 34 93 [2] 2f dd [2] 12 }

  condition:
    any of them
}