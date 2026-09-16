rule TTP_XOR_MULT_DOSStub_6b58 {
  strings:
    $key_6b58 = { 3f 30 [2] 4b 28 [2] 0c 2a [2] 4b 3b [2] 05 37 [2] 09 3d [2] 1e 36 [2] 05 78 [2] 38 }

  condition:
    any of them
}