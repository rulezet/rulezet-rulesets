rule TTP_XOR_MULT_DOSStub_269c {
  strings:
    $key_269c = { 72 f4 [2] 06 ec [2] 41 ee [2] 06 ff [2] 48 f3 [2] 44 f9 [2] 53 f2 [2] 48 bc [2] 75 }

  condition:
    any of them
}