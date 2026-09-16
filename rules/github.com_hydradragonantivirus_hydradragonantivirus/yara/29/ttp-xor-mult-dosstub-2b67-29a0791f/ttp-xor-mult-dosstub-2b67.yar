rule TTP_XOR_MULT_DOSStub_2b67 {
  strings:
    $key_2b67 = { 7f 0f [2] 0b 17 [2] 4c 15 [2] 0b 04 [2] 45 08 [2] 49 02 [2] 5e 09 [2] 45 47 [2] 78 }

  condition:
    any of them
}