rule TTP_XOR_MULT_DOSStub_69cd {
  strings:
    $key_69cd = { 3d a5 [2] 49 bd [2] 0e bf [2] 49 ae [2] 07 a2 [2] 0b a8 [2] 1c a3 [2] 07 ed [2] 3a }

  condition:
    any of them
}