rule TTP_XOR_MULT_DOSStub_696c {
  strings:
    $key_696c = { 3d 04 [2] 49 1c [2] 0e 1e [2] 49 0f [2] 07 03 [2] 0b 09 [2] 1c 02 [2] 07 4c [2] 3a }

  condition:
    any of them
}