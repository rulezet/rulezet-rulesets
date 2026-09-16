rule TTP_XOR_MULT_DOSStub_65ae {
  strings:
    $key_65ae = { 31 c6 [2] 45 de [2] 02 dc [2] 45 cd [2] 0b c1 [2] 07 cb [2] 10 c0 [2] 0b 8e [2] 36 }

  condition:
    any of them
}