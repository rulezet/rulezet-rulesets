rule TTP_XOR_MULT_DOSStub_586b {
  strings:
    $key_586b = { 0c 03 [2] 78 1b [2] 3f 19 [2] 78 08 [2] 36 04 [2] 3a 0e [2] 2d 05 [2] 36 4b [2] 0b }

  condition:
    any of them
}