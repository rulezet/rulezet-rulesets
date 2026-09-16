rule TTP_XOR_MULT_DOSStub_e8ba {
  strings:
    $key_e8ba = { bc d2 [2] c8 ca [2] 8f c8 [2] c8 d9 [2] 86 d5 [2] 8a df [2] 9d d4 [2] 86 9a [2] bb }

  condition:
    any of them
}