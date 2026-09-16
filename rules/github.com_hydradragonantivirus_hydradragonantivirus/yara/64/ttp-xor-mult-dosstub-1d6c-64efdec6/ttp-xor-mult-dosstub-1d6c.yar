rule TTP_XOR_MULT_DOSStub_1d6c {
  strings:
    $key_1d6c = { 49 04 [2] 3d 1c [2] 7a 1e [2] 3d 0f [2] 73 03 [2] 7f 09 [2] 68 02 [2] 73 4c [2] 4e }

  condition:
    any of them
}