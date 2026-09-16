rule TTP_XOR_MULT_DOSStub_006c {
  strings:
    $key_006c = { 54 04 [2] 20 1c [2] 67 1e [2] 20 0f [2] 6e 03 [2] 62 09 [2] 75 02 [2] 6e 4c [2] 53 }

  condition:
    any of them
}