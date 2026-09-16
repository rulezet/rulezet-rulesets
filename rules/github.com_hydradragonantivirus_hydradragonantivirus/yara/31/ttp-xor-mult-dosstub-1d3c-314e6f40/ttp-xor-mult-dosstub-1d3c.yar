rule TTP_XOR_MULT_DOSStub_1d3c {
  strings:
    $key_1d3c = { 49 54 [2] 3d 4c [2] 7a 4e [2] 3d 5f [2] 73 53 [2] 7f 59 [2] 68 52 [2] 73 1c [2] 4e }

  condition:
    any of them
}