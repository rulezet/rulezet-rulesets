rule TTP_XOR_MULT_DOSStub_7dcd {
  strings:
    $key_7dcd = { 29 a5 [2] 5d bd [2] 1a bf [2] 5d ae [2] 13 a2 [2] 1f a8 [2] 08 a3 [2] 13 ed [2] 2e }

  condition:
    any of them
}