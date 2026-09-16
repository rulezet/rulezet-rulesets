rule TTP_XOR_MULT_DOSStub_681d {
  strings:
    $key_681d = { 3c 75 [2] 48 6d [2] 0f 6f [2] 48 7e [2] 06 72 [2] 0a 78 [2] 1d 73 [2] 06 3d [2] 3b }

  condition:
    any of them
}