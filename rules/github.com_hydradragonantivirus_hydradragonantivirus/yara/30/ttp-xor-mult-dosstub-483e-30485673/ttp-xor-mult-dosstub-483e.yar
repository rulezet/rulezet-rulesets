rule TTP_XOR_MULT_DOSStub_483e {
  strings:
    $key_483e = { 1c 56 [2] 68 4e [2] 2f 4c [2] 68 5d [2] 26 51 [2] 2a 5b [2] 3d 50 [2] 26 1e [2] 1b }

  condition:
    any of them
}