rule TTP_XOR_MULT_DOSStub_44cd {
  strings:
    $key_44cd = { 10 a5 [2] 64 bd [2] 23 bf [2] 64 ae [2] 2a a2 [2] 26 a8 [2] 31 a3 [2] 2a ed [2] 17 }

  condition:
    any of them
}