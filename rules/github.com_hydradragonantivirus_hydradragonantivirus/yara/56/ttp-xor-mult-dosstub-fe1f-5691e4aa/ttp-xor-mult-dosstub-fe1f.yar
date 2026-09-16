rule TTP_XOR_MULT_DOSStub_fe1f {
  strings:
    $key_fe1f = { aa 77 [2] de 6f [2] 99 6d [2] de 7c [2] 90 70 [2] 9c 7a [2] 8b 71 [2] 90 3f [2] ad }

  condition:
    any of them
}