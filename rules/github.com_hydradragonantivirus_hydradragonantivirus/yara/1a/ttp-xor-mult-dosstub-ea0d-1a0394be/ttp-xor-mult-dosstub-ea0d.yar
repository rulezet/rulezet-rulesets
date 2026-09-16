rule TTP_XOR_MULT_DOSStub_ea0d {
  strings:
    $key_ea0d = { be 65 [2] ca 7d [2] 8d 7f [2] ca 6e [2] 84 62 [2] 88 68 [2] 9f 63 [2] 84 2d [2] b9 }

  condition:
    any of them
}