rule TTP_XOR_MULT_DOSStub_ebcd {
  strings:
    $key_ebcd = { bf a5 [2] cb bd [2] 8c bf [2] cb ae [2] 85 a2 [2] 89 a8 [2] 9e a3 [2] 85 ed [2] b8 }

  condition:
    any of them
}