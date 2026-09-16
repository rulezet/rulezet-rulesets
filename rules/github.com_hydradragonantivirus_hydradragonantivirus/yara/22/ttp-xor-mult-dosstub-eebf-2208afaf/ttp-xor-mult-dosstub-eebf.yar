rule TTP_XOR_MULT_DOSStub_eebf {
  strings:
    $key_eebf = { ba d7 [2] ce cf [2] 89 cd [2] ce dc [2] 80 d0 [2] 8c da [2] 9b d1 [2] 80 9f [2] bd }

  condition:
    any of them
}