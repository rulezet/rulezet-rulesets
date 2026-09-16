rule TTP_XOR_MULT_DOSStub_cc0a {
  strings:
    $key_cc0a = { 98 62 [2] ec 7a [2] ab 78 [2] ec 69 [2] a2 65 [2] ae 6f [2] b9 64 [2] a2 2a [2] 9f }

  condition:
    any of them
}