rule TTP_XOR_MULT_DOSStub_6fbe {
  strings:
    $key_6fbe = { 3b d6 [2] 4f ce [2] 08 cc [2] 4f dd [2] 01 d1 [2] 0d db [2] 1a d0 [2] 01 9e [2] 3c }

  condition:
    any of them
}