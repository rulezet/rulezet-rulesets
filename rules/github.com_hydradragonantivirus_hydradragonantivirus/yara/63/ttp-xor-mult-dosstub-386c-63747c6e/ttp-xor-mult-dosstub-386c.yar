rule TTP_XOR_MULT_DOSStub_386c {
  strings:
    $key_386c = { 6c 04 [2] 18 1c [2] 5f 1e [2] 18 0f [2] 56 03 [2] 5a 09 [2] 4d 02 [2] 56 4c [2] 6b }

  condition:
    any of them
}