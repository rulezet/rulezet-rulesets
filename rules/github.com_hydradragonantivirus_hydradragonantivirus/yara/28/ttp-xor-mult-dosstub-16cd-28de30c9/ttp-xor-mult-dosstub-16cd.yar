rule TTP_XOR_MULT_DOSStub_16cd {
  strings:
    $key_16cd = { 42 a5 [2] 36 bd [2] 71 bf [2] 36 ae [2] 78 a2 [2] 74 a8 [2] 63 a3 [2] 78 ed [2] 45 }

  condition:
    any of them
}