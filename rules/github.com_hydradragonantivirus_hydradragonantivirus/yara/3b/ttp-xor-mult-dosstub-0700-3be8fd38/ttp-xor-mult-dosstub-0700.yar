rule TTP_XOR_MULT_DOSStub_0700 {
  strings:
    $key_0700 = { 53 68 [2] 27 70 [2] 60 72 [2] 27 63 [2] 69 6f [2] 65 65 [2] 72 6e [2] 69 20 [2] 54 }

  condition:
    any of them
}