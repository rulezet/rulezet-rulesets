rule TTP_XOR_MULT_DOSStub_1d3e {
  strings:
    $key_1d3e = { 49 56 [2] 3d 4e [2] 7a 4c [2] 3d 5d [2] 73 51 [2] 7f 5b [2] 68 50 [2] 73 1e [2] 4e }

  condition:
    any of them
}