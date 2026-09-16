rule TTP_XOR_MULT_DOSStub_38cd {
  strings:
    $key_38cd = { 6c a5 [2] 18 bd [2] 5f bf [2] 18 ae [2] 56 a2 [2] 5a a8 [2] 4d a3 [2] 56 ed [2] 6b }

  condition:
    any of them
}