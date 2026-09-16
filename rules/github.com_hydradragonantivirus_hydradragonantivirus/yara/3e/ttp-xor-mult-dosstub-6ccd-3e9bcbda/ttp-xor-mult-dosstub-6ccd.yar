rule TTP_XOR_MULT_DOSStub_6ccd {
  strings:
    $key_6ccd = { 38 a5 [2] 4c bd [2] 0b bf [2] 4c ae [2] 02 a2 [2] 0e a8 [2] 19 a3 [2] 02 ed [2] 3f }

  condition:
    any of them
}