rule TTP_XOR_MULT_DOSStub_ea4d {
  strings:
    $key_ea4d = { be 25 [2] ca 3d [2] 8d 3f [2] ca 2e [2] 84 22 [2] 88 28 [2] 9f 23 [2] 84 6d [2] b9 }

  condition:
    any of them
}