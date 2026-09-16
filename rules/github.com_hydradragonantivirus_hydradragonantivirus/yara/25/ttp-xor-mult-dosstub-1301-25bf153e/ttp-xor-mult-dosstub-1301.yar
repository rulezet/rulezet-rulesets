rule TTP_XOR_MULT_DOSStub_1301 {
  strings:
    $key_1301 = { 47 69 [2] 33 71 [2] 74 73 [2] 33 62 [2] 7d 6e [2] 71 64 [2] 66 6f [2] 7d 21 [2] 40 }

  condition:
    any of them
}