rule TTP_XOR_MULT_DOSStub_e86c {
  strings:
    $key_e86c = { bc 04 [2] c8 1c [2] 8f 1e [2] c8 0f [2] 86 03 [2] 8a 09 [2] 9d 02 [2] 86 4c [2] bb }

  condition:
    any of them
}