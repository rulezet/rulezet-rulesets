rule TTP_XOR_MULT_DOSStub_ccff {
  strings:
    $key_ccff = { 98 97 [2] ec 8f [2] ab 8d [2] ec 9c [2] a2 90 [2] ae 9a [2] b9 91 [2] a2 df [2] 9f }

  condition:
    any of them
}