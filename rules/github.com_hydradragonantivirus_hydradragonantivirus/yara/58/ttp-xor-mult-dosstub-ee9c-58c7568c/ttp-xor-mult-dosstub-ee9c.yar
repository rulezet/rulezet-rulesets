rule TTP_XOR_MULT_DOSStub_ee9c {
  strings:
    $key_ee9c = { ba f4 [2] ce ec [2] 89 ee [2] ce ff [2] 80 f3 [2] 8c f9 [2] 9b f2 [2] 80 bc [2] bd }

  condition:
    any of them
}