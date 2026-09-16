rule TTP_XOR_MULT_DOSStub_1da3 {
  strings:
    $key_1da3 = { 49 cb [2] 3d d3 [2] 7a d1 [2] 3d c0 [2] 73 cc [2] 7f c6 [2] 68 cd [2] 73 83 [2] 4e }

  condition:
    any of them
}