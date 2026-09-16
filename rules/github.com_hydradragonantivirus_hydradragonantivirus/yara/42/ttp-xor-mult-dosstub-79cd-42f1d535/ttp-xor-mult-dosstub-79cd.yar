rule TTP_XOR_MULT_DOSStub_79cd {
  strings:
    $key_79cd = { 2d a5 [2] 59 bd [2] 1e bf [2] 59 ae [2] 17 a2 [2] 1b a8 [2] 0c a3 [2] 17 ed [2] 2a }

  condition:
    any of them
}