rule TTP_XOR_MULT_DOSStub_6551 {
  strings:
    $key_6551 = { 31 39 [2] 45 21 [2] 02 23 [2] 45 32 [2] 0b 3e [2] 07 34 [2] 10 3f [2] 0b 71 [2] 36 }

  condition:
    any of them
}