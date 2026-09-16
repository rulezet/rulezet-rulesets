rule TTP_XOR_MULT_DOSStub_fe3e {
  strings:
    $key_fe3e = { aa 56 [2] de 4e [2] 99 4c [2] de 5d [2] 90 51 [2] 9c 5b [2] 8b 50 [2] 90 1e [2] ad }

  condition:
    any of them
}