rule TTP_XOR_MULT_DOSStub_3d3e {
  strings:
    $key_3d3e = { 69 56 [2] 1d 4e [2] 5a 4c [2] 1d 5d [2] 53 51 [2] 5f 5b [2] 48 50 [2] 53 1e [2] 6e }

  condition:
    any of them
}