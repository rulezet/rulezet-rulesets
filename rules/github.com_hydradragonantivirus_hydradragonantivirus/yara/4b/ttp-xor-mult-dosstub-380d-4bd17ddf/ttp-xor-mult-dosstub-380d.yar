rule TTP_XOR_MULT_DOSStub_380d {
  strings:
    $key_380d = { 6c 65 [2] 18 7d [2] 5f 7f [2] 18 6e [2] 56 62 [2] 5a 68 [2] 4d 63 [2] 56 2d [2] 6b }

  condition:
    any of them
}