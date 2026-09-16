rule TTP_XOR_MULT_DOSStub_6167 {
  strings:
    $key_6167 = { 35 0f [2] 41 17 [2] 06 15 [2] 41 04 [2] 0f 08 [2] 03 02 [2] 14 09 [2] 0f 47 [2] 32 }

  condition:
    any of them
}