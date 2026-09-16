rule TTP_XOR_MULT_DOSStub_29e0 {
  strings:
    $key_29e0 = { 7d 88 [2] 09 90 [2] 4e 92 [2] 09 83 [2] 47 8f [2] 4b 85 [2] 5c 8e [2] 47 c0 [2] 7a }

  condition:
    any of them
}