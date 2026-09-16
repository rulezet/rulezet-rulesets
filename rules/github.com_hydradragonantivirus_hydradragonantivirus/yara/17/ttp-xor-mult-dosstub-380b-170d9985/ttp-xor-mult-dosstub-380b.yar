rule TTP_XOR_MULT_DOSStub_380b {
  strings:
    $key_380b = { 6c 63 [2] 18 7b [2] 5f 79 [2] 18 68 [2] 56 64 [2] 5a 6e [2] 4d 65 [2] 56 2b [2] 6b }

  condition:
    any of them
}