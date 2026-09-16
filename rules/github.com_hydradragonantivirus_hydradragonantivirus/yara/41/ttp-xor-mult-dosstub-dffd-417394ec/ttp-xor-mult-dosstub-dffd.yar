rule TTP_XOR_MULT_DOSStub_dffd {
  strings:
    $key_dffd = { 8b 95 [2] ff 8d [2] b8 8f [2] ff 9e [2] b1 92 [2] bd 98 [2] aa 93 [2] b1 dd [2] 8c }

  condition:
    any of them
}