rule TTP_XOR_MULT_DOSStub_536c {
  strings:
    $key_536c = { 07 04 [2] 73 1c [2] 34 1e [2] 73 0f [2] 3d 03 [2] 31 09 [2] 26 02 [2] 3d 4c [2] 00 }

  condition:
    any of them
}