rule TTP_XOR_MULT_DOSStub_379c {
  strings:
    $key_379c = { 63 f4 [2] 17 ec [2] 50 ee [2] 17 ff [2] 59 f3 [2] 55 f9 [2] 42 f2 [2] 59 bc [2] 64 }

  condition:
    any of them
}