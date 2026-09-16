rule TTP_XOR_MULT_DOSStub_43cd {
  strings:
    $key_43cd = { 17 a5 [2] 63 bd [2] 24 bf [2] 63 ae [2] 2d a2 [2] 21 a8 [2] 36 a3 [2] 2d ed [2] 10 }

  condition:
    any of them
}