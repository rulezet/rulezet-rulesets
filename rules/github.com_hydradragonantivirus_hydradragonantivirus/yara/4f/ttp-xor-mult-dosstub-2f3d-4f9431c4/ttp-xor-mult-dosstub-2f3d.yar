rule TTP_XOR_MULT_DOSStub_2f3d {
  strings:
    $key_2f3d = { 7b 55 [2] 0f 4d [2] 48 4f [2] 0f 5e [2] 41 52 [2] 4d 58 [2] 5a 53 [2] 41 1d [2] 7c }

  condition:
    any of them
}