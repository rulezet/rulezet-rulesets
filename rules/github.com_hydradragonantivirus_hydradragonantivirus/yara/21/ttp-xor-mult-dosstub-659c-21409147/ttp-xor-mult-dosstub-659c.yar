rule TTP_XOR_MULT_DOSStub_659c {
  strings:
    $key_659c = { 31 f4 [2] 45 ec [2] 02 ee [2] 45 ff [2] 0b f3 [2] 07 f9 [2] 10 f2 [2] 0b bc [2] 36 }

  condition:
    any of them
}