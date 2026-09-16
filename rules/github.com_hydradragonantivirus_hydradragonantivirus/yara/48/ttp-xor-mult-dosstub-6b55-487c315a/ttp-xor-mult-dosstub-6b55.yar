rule TTP_XOR_MULT_DOSStub_6b55 {
  strings:
    $key_6b55 = { 3f 3d [2] 4b 25 [2] 0c 27 [2] 4b 36 [2] 05 3a [2] 09 30 [2] 1e 3b [2] 05 75 [2] 38 }

  condition:
    any of them
}