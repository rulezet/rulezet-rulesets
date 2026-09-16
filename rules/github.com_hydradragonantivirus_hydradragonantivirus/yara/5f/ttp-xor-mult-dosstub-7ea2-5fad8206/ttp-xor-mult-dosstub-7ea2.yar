rule TTP_XOR_MULT_DOSStub_7ea2 {
  strings:
    $key_7ea2 = { 2a ca [2] 5e d2 [2] 19 d0 [2] 5e c1 [2] 10 cd [2] 1c c7 [2] 0b cc [2] 10 82 [2] 2d }

  condition:
    any of them
}