rule TTP_XOR_MULT_DOSStub_3ccd {
  strings:
    $key_3ccd = { 68 a5 [2] 1c bd [2] 5b bf [2] 1c ae [2] 52 a2 [2] 5e a8 [2] 49 a3 [2] 52 ed [2] 6f }

  condition:
    any of them
}