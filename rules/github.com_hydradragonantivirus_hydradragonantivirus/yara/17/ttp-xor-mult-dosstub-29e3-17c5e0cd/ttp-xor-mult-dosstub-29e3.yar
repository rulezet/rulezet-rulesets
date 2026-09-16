rule TTP_XOR_MULT_DOSStub_29e3 {
  strings:
    $key_29e3 = { 7d 8b [2] 09 93 [2] 4e 91 [2] 09 80 [2] 47 8c [2] 4b 86 [2] 5c 8d [2] 47 c3 [2] 7a }

  condition:
    any of them
}