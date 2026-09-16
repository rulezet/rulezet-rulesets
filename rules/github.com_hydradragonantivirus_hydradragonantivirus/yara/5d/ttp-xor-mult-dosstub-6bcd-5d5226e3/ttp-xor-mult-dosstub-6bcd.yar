rule TTP_XOR_MULT_DOSStub_6bcd {
  strings:
    $key_6bcd = { 3f a5 [2] 4b bd [2] 0c bf [2] 4b ae [2] 05 a2 [2] 09 a8 [2] 1e a3 [2] 05 ed [2] 38 }

  condition:
    any of them
}