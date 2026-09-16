rule TTP_XOR_MULT_DOSStub_6ea2 {
  strings:
    $key_6ea2 = { 3a ca [2] 4e d2 [2] 09 d0 [2] 4e c1 [2] 00 cd [2] 0c c7 [2] 1b cc [2] 00 82 [2] 3d }

  condition:
    any of them
}