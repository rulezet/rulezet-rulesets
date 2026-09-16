rule TTP_XOR_MULT_DOSStub_696d {
  strings:
    $key_696d = { 3d 05 [2] 49 1d [2] 0e 1f [2] 49 0e [2] 07 02 [2] 0b 08 [2] 1c 03 [2] 07 4d [2] 3a }

  condition:
    any of them
}