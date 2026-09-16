rule TTP_XOR_MULT_DOSStub_3d6c {
  strings:
    $key_3d6c = { 69 04 [2] 1d 1c [2] 5a 1e [2] 1d 0f [2] 53 03 [2] 5f 09 [2] 48 02 [2] 53 4c [2] 6e }

  condition:
    any of them
}