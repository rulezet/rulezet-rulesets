rule TTP_XOR_MULT_DOSStub_0667 {
  strings:
    $key_0667 = { 52 0f [2] 26 17 [2] 61 15 [2] 26 04 [2] 68 08 [2] 64 02 [2] 73 09 [2] 68 47 [2] 55 }

  condition:
    any of them
}