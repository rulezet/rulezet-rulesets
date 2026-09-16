rule TTP_XOR_MULT_DOSStub_6ed5 {
  strings:
    $key_6ed5 = { 3a bd [2] 4e a5 [2] 09 a7 [2] 4e b6 [2] 00 ba [2] 0c b0 [2] 1b bb [2] 00 f5 [2] 3d }

  condition:
    any of them
}