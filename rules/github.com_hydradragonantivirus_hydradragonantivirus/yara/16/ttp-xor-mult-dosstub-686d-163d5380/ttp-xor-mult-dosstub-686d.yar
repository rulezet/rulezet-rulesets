rule TTP_XOR_MULT_DOSStub_686d {
  strings:
    $key_686d = { 3c 05 [2] 48 1d [2] 0f 1f [2] 48 0e [2] 06 02 [2] 0a 08 [2] 1d 03 [2] 06 4d [2] 3b }

  condition:
    any of them
}