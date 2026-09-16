rule TTP_XOR_MULT_DOSStub_532b {
  strings:
    $key_532b = { 07 43 [2] 73 5b [2] 34 59 [2] 73 48 [2] 3d 44 [2] 31 4e [2] 26 45 [2] 3d 0b [2] 00 }

  condition:
    any of them
}