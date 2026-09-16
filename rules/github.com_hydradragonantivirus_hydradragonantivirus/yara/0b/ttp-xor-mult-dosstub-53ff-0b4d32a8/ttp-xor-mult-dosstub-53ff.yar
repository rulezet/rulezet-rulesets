rule TTP_XOR_MULT_DOSStub_53ff {
  strings:
    $key_53ff = { 07 97 [2] 73 8f [2] 34 8d [2] 73 9c [2] 3d 90 [2] 31 9a [2] 26 91 [2] 3d df [2] 00 }

  condition:
    any of them
}