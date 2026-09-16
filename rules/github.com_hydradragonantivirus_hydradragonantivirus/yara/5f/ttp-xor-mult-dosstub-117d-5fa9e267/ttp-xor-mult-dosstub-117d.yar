rule TTP_XOR_MULT_DOSStub_117d {
  strings:
    $key_117d = { 45 15 [2] 31 0d [2] 76 0f [2] 31 1e [2] 7f 12 [2] 73 18 [2] 64 13 [2] 7f 5d [2] 42 }

  condition:
    any of them
}