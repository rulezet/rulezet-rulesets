rule TTP_XOR_MULT_DOSStub_1dcd {
  strings:
    $key_1dcd = { 49 a5 [2] 3d bd [2] 7a bf [2] 3d ae [2] 73 a2 [2] 7f a8 [2] 68 a3 [2] 73 ed [2] 4e }

  condition:
    any of them
}