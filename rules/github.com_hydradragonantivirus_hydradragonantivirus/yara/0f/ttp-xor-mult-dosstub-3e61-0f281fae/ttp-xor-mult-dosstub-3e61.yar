rule TTP_XOR_MULT_DOSStub_3e61 {
  strings:
    $key_3e61 = { 6a 09 [2] 1e 11 [2] 59 13 [2] 1e 02 [2] 50 0e [2] 5c 04 [2] 4b 0f [2] 50 41 [2] 6d }

  condition:
    any of them
}