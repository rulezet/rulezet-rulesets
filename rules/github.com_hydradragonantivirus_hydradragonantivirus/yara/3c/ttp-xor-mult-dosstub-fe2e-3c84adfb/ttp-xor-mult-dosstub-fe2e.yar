rule TTP_XOR_MULT_DOSStub_fe2e {
  strings:
    $key_fe2e = { aa 46 [2] de 5e [2] 99 5c [2] de 4d [2] 90 41 [2] 9c 4b [2] 8b 40 [2] 90 0e [2] ad }

  condition:
    any of them
}