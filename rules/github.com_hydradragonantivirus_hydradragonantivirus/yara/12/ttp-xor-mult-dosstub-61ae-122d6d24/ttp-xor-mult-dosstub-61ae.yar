rule TTP_XOR_MULT_DOSStub_61ae {
  strings:
    $key_61ae = { 35 c6 [2] 41 de [2] 06 dc [2] 41 cd [2] 0f c1 [2] 03 cb [2] 14 c0 [2] 0f 8e [2] 32 }

  condition:
    any of them
}