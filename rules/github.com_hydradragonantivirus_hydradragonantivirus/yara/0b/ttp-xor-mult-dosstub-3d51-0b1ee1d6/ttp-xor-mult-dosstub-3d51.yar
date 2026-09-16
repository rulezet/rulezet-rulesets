rule TTP_XOR_MULT_DOSStub_3d51 {
  strings:
    $key_3d51 = { 69 39 [2] 1d 21 [2] 5a 23 [2] 1d 32 [2] 53 3e [2] 5f 34 [2] 48 3f [2] 53 71 [2] 6e }

  condition:
    any of them
}