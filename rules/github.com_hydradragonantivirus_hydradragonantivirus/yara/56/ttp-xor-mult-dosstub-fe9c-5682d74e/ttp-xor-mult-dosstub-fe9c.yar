rule TTP_XOR_MULT_DOSStub_fe9c {
  strings:
    $key_fe9c = { aa f4 [2] de ec [2] 99 ee [2] de ff [2] 90 f3 [2] 9c f9 [2] 8b f2 [2] 90 bc [2] ad }

  condition:
    any of them
}