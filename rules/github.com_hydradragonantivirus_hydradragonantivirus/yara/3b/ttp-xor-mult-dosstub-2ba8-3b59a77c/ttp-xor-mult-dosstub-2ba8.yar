rule TTP_XOR_MULT_DOSStub_2ba8 {
  strings:
    $key_2ba8 = { 7f c0 [2] 0b d8 [2] 4c da [2] 0b cb [2] 45 c7 [2] 49 cd [2] 5e c6 [2] 45 88 [2] 78 }

  condition:
    any of them
}