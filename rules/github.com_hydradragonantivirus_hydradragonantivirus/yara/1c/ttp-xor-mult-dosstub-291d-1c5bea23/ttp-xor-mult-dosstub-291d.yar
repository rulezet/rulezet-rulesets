rule TTP_XOR_MULT_DOSStub_291d {
  strings:
    $key_291d = { 7d 75 [2] 09 6d [2] 4e 6f [2] 09 7e [2] 47 72 [2] 4b 78 [2] 5c 73 [2] 47 3d [2] 7a }

  condition:
    any of them
}