rule TTP_XOR_MULT_DOSStub_53fe {
  strings:
    $key_53fe = { 07 96 [2] 73 8e [2] 34 8c [2] 73 9d [2] 3d 91 [2] 31 9b [2] 26 90 [2] 3d de [2] 00 }

  condition:
    any of them
}