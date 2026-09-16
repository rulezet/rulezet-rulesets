rule TTP_XOR_MULT_DOSStub_613e {
  strings:
    $key_613e = { 35 56 [2] 41 4e [2] 06 4c [2] 41 5d [2] 0f 51 [2] 03 5b [2] 14 50 [2] 0f 1e [2] 32 }

  condition:
    any of them
}