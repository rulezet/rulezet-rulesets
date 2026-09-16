rule TTP_XOR_MULT_DOSStub_016c {
  strings:
    $key_016c = { 55 04 [2] 21 1c [2] 66 1e [2] 21 0f [2] 6f 03 [2] 63 09 [2] 74 02 [2] 6f 4c [2] 52 }

  condition:
    any of them
}