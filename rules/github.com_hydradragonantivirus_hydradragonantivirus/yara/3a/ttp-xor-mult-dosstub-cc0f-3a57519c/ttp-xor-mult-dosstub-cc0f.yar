rule TTP_XOR_MULT_DOSStub_cc0f {
  strings:
    $key_cc0f = { 98 67 [2] ec 7f [2] ab 7d [2] ec 6c [2] a2 60 [2] ae 6a [2] b9 61 [2] a2 2f [2] 9f }

  condition:
    any of them
}