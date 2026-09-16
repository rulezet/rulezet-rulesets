rule TTP_XOR_MULT_DOSStub_3d61 {
  strings:
    $key_3d61 = { 69 09 [2] 1d 11 [2] 5a 13 [2] 1d 02 [2] 53 0e [2] 5f 04 [2] 48 0f [2] 53 41 [2] 6e }

  condition:
    any of them
}