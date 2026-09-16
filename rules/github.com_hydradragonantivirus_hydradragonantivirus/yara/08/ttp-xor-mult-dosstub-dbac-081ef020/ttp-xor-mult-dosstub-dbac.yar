rule TTP_XOR_MULT_DOSStub_dbac {
  strings:
    $key_dbac = { 8f c4 [2] fb dc [2] bc de [2] fb cf [2] b5 c3 [2] b9 c9 [2] ae c2 [2] b5 8c [2] 88 }

  condition:
    any of them
}