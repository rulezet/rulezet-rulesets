rule TTP_XOR_MULT_DOSStub_716b {
  strings:
    $key_716b = { 25 03 [2] 51 1b [2] 16 19 [2] 51 08 [2] 1f 04 [2] 13 0e [2] 04 05 [2] 1f 4b [2] 22 }

  condition:
    any of them
}