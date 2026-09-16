rule TTP_XOR_MULT_DOSStub_6ed3 {
  strings:
    $key_6ed3 = { 3a bb [2] 4e a3 [2] 09 a1 [2] 4e b0 [2] 00 bc [2] 0c b6 [2] 1b bd [2] 00 f3 [2] 3d }

  condition:
    any of them
}