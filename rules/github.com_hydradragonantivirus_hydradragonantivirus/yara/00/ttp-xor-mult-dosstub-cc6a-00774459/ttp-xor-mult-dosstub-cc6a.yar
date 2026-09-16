rule TTP_XOR_MULT_DOSStub_cc6a {
  strings:
    $key_cc6a = { 98 02 [2] ec 1a [2] ab 18 [2] ec 09 [2] a2 05 [2] ae 0f [2] b9 04 [2] a2 4a [2] 9f }

  condition:
    any of them
}