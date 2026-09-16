rule TTP_XOR_MULT_DOSStub_0dcd {
  strings:
    $key_0dcd = { 59 a5 [2] 2d bd [2] 6a bf [2] 2d ae [2] 63 a2 [2] 6f a8 [2] 78 a3 [2] 63 ed [2] 5e }

  condition:
    any of them
}