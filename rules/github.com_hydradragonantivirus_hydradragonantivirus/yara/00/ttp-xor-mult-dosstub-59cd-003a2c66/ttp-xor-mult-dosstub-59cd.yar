rule TTP_XOR_MULT_DOSStub_59cd {
  strings:
    $key_59cd = { 0d a5 [2] 79 bd [2] 3e bf [2] 79 ae [2] 37 a2 [2] 3b a8 [2] 2c a3 [2] 37 ed [2] 0a }

  condition:
    any of them
}