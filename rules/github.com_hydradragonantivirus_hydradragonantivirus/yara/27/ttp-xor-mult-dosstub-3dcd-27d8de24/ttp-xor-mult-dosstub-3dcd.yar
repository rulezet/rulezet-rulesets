rule TTP_XOR_MULT_DOSStub_3dcd {
  strings:
    $key_3dcd = { 69 a5 [2] 1d bd [2] 5a bf [2] 1d ae [2] 53 a2 [2] 5f a8 [2] 48 a3 [2] 53 ed [2] 6e }

  condition:
    any of them
}