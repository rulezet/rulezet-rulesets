rule TTP_XOR_MULT_DOSStub_69fd {
  strings:
    $key_69fd = { 3d 95 [2] 49 8d [2] 0e 8f [2] 49 9e [2] 07 92 [2] 0b 98 [2] 1c 93 [2] 07 dd [2] 3a }

  condition:
    any of them
}