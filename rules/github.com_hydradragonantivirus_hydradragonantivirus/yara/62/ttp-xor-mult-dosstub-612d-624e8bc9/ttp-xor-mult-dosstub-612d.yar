rule TTP_XOR_MULT_DOSStub_612d {
  strings:
    $key_612d = { 35 45 [2] 41 5d [2] 06 5f [2] 41 4e [2] 0f 42 [2] 03 48 [2] 14 43 [2] 0f 0d [2] 32 }

  condition:
    any of them
}