rule TTP_XOR_MULT_DOSStub_34cd {
  strings:
    $key_34cd = { 60 a5 [2] 14 bd [2] 53 bf [2] 14 ae [2] 5a a2 [2] 56 a8 [2] 41 a3 [2] 5a ed [2] 67 }

  condition:
    any of them
}