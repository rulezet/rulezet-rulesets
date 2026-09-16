rule TTP_XOR_MULT_DOSStub_cdec {
  strings:
    $key_cdec = { 99 84 [2] ed 9c [2] aa 9e [2] ed 8f [2] a3 83 [2] af 89 [2] b8 82 [2] a3 cc [2] 9e }

  condition:
    any of them
}