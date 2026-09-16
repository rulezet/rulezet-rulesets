rule TTP_XOR_MULT_DOSStub_61fc {
  strings:
    $key_61fc = { 35 94 [2] 41 8c [2] 06 8e [2] 41 9f [2] 0f 93 [2] 03 99 [2] 14 92 [2] 0f dc [2] 32 }

  condition:
    any of them
}