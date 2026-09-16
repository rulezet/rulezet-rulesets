rule TTP_XOR_MULT_DOSStub_166c {
  strings:
    $key_166c = { 42 04 [2] 36 1c [2] 71 1e [2] 36 0f [2] 78 03 [2] 74 09 [2] 63 02 [2] 78 4c [2] 45 }

  condition:
    any of them
}