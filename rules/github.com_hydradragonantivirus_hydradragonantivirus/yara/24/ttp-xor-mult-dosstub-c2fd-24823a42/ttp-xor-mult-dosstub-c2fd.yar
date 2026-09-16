rule TTP_XOR_MULT_DOSStub_c2fd {
  strings:
    $key_c2fd = { 96 95 [2] e2 8d [2] a5 8f [2] e2 9e [2] ac 92 [2] a0 98 [2] b7 93 [2] ac dd [2] 91 }

  condition:
    any of them
}