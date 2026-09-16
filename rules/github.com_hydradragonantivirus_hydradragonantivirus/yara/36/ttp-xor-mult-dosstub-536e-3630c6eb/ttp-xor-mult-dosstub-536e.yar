rule TTP_XOR_MULT_DOSStub_536e {
  strings:
    $key_536e = { 07 06 [2] 73 1e [2] 34 1c [2] 73 0d [2] 3d 01 [2] 31 0b [2] 26 00 [2] 3d 4e [2] 00 }

  condition:
    any of them
}