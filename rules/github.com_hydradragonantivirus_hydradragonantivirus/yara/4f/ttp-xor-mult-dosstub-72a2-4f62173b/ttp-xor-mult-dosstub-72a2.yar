rule TTP_XOR_MULT_DOSStub_72a2 {
  strings:
    $key_72a2 = { 26 ca [2] 52 d2 [2] 15 d0 [2] 52 c1 [2] 1c cd [2] 10 c7 [2] 07 cc [2] 1c 82 [2] 21 }

  condition:
    any of them
}