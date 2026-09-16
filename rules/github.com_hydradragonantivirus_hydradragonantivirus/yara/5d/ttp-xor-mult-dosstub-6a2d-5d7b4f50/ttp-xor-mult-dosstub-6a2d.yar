rule TTP_XOR_MULT_DOSStub_6a2d {
  strings:
    $key_6a2d = { 3e 45 [2] 4a 5d [2] 0d 5f [2] 4a 4e [2] 04 42 [2] 08 48 [2] 1f 43 [2] 04 0d [2] 39 }

  condition:
    any of them
}