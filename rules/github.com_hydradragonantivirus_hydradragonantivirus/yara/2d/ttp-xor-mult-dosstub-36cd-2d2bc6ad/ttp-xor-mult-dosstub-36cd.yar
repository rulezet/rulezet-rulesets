rule TTP_XOR_MULT_DOSStub_36cd {
  strings:
    $key_36cd = { 62 a5 [2] 16 bd [2] 51 bf [2] 16 ae [2] 58 a2 [2] 54 a8 [2] 43 a3 [2] 58 ed [2] 65 }

  condition:
    any of them
}