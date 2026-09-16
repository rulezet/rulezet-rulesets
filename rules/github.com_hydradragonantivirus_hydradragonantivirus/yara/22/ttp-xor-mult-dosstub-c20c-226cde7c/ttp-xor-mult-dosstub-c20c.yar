rule TTP_XOR_MULT_DOSStub_c20c {
  strings:
    $key_c20c = { 96 64 [2] e2 7c [2] a5 7e [2] e2 6f [2] ac 63 [2] a0 69 [2] b7 62 [2] ac 2c [2] 91 }

  condition:
    any of them
}