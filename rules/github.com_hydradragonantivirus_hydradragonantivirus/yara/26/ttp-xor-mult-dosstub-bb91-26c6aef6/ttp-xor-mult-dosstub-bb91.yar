rule TTP_XOR_MULT_DOSStub_bb91 {
  strings:
    $key_bb91 = { ef f9 [2] 9b e1 [2] dc e3 [2] 9b f2 [2] d5 fe [2] d9 f4 [2] ce ff [2] d5 b1 [2] e8 }

  condition:
    any of them
}