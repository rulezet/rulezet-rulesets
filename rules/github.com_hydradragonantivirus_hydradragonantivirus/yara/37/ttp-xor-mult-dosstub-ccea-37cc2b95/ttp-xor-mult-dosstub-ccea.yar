rule TTP_XOR_MULT_DOSStub_ccea {
  strings:
    $key_ccea = { 98 82 [2] ec 9a [2] ab 98 [2] ec 89 [2] a2 85 [2] ae 8f [2] b9 84 [2] a2 ca [2] 9f }

  condition:
    any of them
}