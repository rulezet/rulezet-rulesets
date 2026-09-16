rule TTP_XOR_MULT_DOSStub_1ccd {
  strings:
    $key_1ccd = { 48 a5 [2] 3c bd [2] 7b bf [2] 3c ae [2] 72 a2 [2] 7e a8 [2] 69 a3 [2] 72 ed [2] 4f }

  condition:
    any of them
}