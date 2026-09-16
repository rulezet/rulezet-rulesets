rule TTP_XOR_MULT_DOSStub_5121 {
  strings:
    $key_5121 = { 05 49 [2] 71 51 [2] 36 53 [2] 71 42 [2] 3f 4e [2] 33 44 [2] 24 4f [2] 3f 01 [2] 02 }

  condition:
    any of them
}