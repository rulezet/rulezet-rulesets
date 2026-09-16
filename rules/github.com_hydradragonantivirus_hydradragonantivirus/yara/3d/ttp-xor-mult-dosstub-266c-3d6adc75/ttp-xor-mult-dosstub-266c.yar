rule TTP_XOR_MULT_DOSStub_266c {
  strings:
    $key_266c = { 72 04 [2] 06 1c [2] 41 1e [2] 06 0f [2] 48 03 [2] 44 09 [2] 53 02 [2] 48 4c [2] 75 }

  condition:
    any of them
}