rule TTP_XOR_MULT_DOSStub_6d2d {
  strings:
    $key_6d2d = { 39 45 [2] 4d 5d [2] 0a 5f [2] 4d 4e [2] 03 42 [2] 0f 48 [2] 18 43 [2] 03 0d [2] 3e }

  condition:
    any of them
}