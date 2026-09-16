rule TTP_XOR_MULT_DOSStub_cccc {
  strings:
    $key_cccc = { 98 a4 [2] ec bc [2] ab be [2] ec af [2] a2 a3 [2] ae a9 [2] b9 a2 [2] a2 ec [2] 9f }

  condition:
    any of them
}