rule TTP_XOR_MULT_DOSStub_e826 {
  strings:
    $key_e826 = { bc 4e [2] c8 56 [2] 8f 54 [2] c8 45 [2] 86 49 [2] 8a 43 [2] 9d 48 [2] 86 06 [2] bb }

  condition:
    any of them
}