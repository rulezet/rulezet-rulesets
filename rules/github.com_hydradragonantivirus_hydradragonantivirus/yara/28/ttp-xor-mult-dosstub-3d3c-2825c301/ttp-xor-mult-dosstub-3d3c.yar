rule TTP_XOR_MULT_DOSStub_3d3c {
  strings:
    $key_3d3c = { 69 54 [2] 1d 4c [2] 5a 4e [2] 1d 5f [2] 53 53 [2] 5f 59 [2] 48 52 [2] 53 1c [2] 6e }

  condition:
    any of them
}