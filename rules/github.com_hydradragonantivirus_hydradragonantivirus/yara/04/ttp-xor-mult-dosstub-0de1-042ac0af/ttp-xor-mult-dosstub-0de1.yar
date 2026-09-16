rule TTP_XOR_MULT_DOSStub_0de1 {
  strings:
    $key_0de1 = { 59 89 [2] 2d 91 [2] 6a 93 [2] 2d 82 [2] 63 8e [2] 6f 84 [2] 78 8f [2] 63 c1 [2] 5e }

  condition:
    any of them
}