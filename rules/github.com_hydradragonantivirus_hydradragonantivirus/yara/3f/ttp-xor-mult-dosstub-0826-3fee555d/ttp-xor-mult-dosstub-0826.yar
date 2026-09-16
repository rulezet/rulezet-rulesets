rule TTP_XOR_MULT_DOSStub_0826 {
  strings:
    $key_0826 = { 5c 4e [2] 28 56 [2] 6f 54 [2] 28 45 [2] 66 49 [2] 6a 43 [2] 7d 48 [2] 66 06 [2] 5b }

  condition:
    any of them
}