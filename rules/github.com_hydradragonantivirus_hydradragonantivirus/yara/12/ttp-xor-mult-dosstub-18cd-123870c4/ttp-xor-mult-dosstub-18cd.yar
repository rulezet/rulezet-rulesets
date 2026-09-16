rule TTP_XOR_MULT_DOSStub_18cd {
  strings:
    $key_18cd = { 4c a5 [2] 38 bd [2] 7f bf [2] 38 ae [2] 76 a2 [2] 7a a8 [2] 6d a3 [2] 76 ed [2] 4b }

  condition:
    any of them
}