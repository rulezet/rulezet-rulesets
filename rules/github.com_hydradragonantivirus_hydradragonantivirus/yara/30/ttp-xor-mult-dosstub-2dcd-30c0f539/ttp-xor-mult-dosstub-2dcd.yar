rule TTP_XOR_MULT_DOSStub_2dcd {
  strings:
    $key_2dcd = { 79 a5 [2] 0d bd [2] 4a bf [2] 0d ae [2] 43 a2 [2] 4f a8 [2] 58 a3 [2] 43 ed [2] 7e }

  condition:
    any of them
}