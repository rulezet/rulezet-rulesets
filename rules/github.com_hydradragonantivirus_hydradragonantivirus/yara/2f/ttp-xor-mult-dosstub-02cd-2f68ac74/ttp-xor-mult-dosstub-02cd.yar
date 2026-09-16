rule TTP_XOR_MULT_DOSStub_02cd {
  strings:
    $key_02cd = { 56 a5 [2] 22 bd [2] 65 bf [2] 22 ae [2] 6c a2 [2] 60 a8 [2] 77 a3 [2] 6c ed [2] 51 }

  condition:
    any of them
}