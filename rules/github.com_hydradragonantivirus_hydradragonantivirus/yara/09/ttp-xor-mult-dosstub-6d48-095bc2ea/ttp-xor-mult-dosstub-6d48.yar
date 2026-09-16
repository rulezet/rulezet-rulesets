rule TTP_XOR_MULT_DOSStub_6d48 {
  strings:
    $key_6d48 = { 39 20 [2] 4d 38 [2] 0a 3a [2] 4d 2b [2] 03 27 [2] 0f 2d [2] 18 26 [2] 03 68 [2] 3e }

  condition:
    any of them
}