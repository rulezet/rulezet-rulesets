rule TTP_XOR_MULT_DOSStub_fe5e {
  strings:
    $key_fe5e = { aa 36 [2] de 2e [2] 99 2c [2] de 3d [2] 90 31 [2] 9c 3b [2] 8b 30 [2] 90 7e [2] ad }

  condition:
    any of them
}