rule TTP_XOR_MULT_DOSStub_2ba9 {
  strings:
    $key_2ba9 = { 7f c1 [2] 0b d9 [2] 4c db [2] 0b ca [2] 45 c6 [2] 49 cc [2] 5e c7 [2] 45 89 [2] 78 }

  condition:
    any of them
}