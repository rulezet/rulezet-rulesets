rule TTP_XOR_MULT_DOSStub_2b58 {
  strings:
    $key_2b58 = { 7f 30 [2] 0b 28 [2] 4c 2a [2] 0b 3b [2] 45 37 [2] 49 3d [2] 5e 36 [2] 45 78 [2] 78 }

  condition:
    any of them
}