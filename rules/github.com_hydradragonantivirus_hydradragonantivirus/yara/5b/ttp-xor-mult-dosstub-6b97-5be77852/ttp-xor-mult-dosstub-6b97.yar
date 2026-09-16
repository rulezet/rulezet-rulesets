rule TTP_XOR_MULT_DOSStub_6b97 {
  strings:
    $key_6b97 = { 3f ff [2] 4b e7 [2] 0c e5 [2] 4b f4 [2] 05 f8 [2] 09 f2 [2] 1e f9 [2] 05 b7 [2] 38 }

  condition:
    any of them
}