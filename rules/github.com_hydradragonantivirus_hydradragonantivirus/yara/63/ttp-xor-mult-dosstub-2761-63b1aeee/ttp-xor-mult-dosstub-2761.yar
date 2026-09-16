rule TTP_XOR_MULT_DOSStub_2761 {
  strings:
    $key_2761 = { 73 09 [2] 07 11 [2] 40 13 [2] 07 02 [2] 49 0e [2] 45 04 [2] 52 0f [2] 49 41 [2] 74 }

  condition:
    any of them
}