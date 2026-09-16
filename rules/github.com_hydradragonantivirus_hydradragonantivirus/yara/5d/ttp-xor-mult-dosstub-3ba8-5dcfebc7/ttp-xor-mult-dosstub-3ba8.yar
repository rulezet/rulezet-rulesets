rule TTP_XOR_MULT_DOSStub_3ba8 {
  strings:
    $key_3ba8 = { 6f c0 [2] 1b d8 [2] 5c da [2] 1b cb [2] 55 c7 [2] 59 cd [2] 4e c6 [2] 55 88 [2] 68 }

  condition:
    any of them
}