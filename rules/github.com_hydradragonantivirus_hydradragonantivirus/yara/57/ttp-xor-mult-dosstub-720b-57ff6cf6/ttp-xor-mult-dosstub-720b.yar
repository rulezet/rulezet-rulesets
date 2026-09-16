rule TTP_XOR_MULT_DOSStub_720b {
  strings:
    $key_720b = { 26 63 [2] 52 7b [2] 15 79 [2] 52 68 [2] 1c 64 [2] 10 6e [2] 07 65 [2] 1c 2b [2] 21 }

  condition:
    any of them
}