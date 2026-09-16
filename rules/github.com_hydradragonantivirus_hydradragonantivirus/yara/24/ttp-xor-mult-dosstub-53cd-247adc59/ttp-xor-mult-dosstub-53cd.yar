rule TTP_XOR_MULT_DOSStub_53cd {
  strings:
    $key_53cd = { 07 a5 [2] 73 bd [2] 34 bf [2] 73 ae [2] 3d a2 [2] 31 a8 [2] 26 a3 [2] 3d ed [2] 00 }

  condition:
    any of them
}