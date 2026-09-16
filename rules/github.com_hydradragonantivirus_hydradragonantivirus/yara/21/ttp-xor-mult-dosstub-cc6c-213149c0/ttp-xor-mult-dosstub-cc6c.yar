rule TTP_XOR_MULT_DOSStub_cc6c {
  strings:
    $key_cc6c = { 98 04 [2] ec 1c [2] ab 1e [2] ec 0f [2] a2 03 [2] ae 09 [2] b9 02 [2] a2 4c [2] 9f }

  condition:
    any of them
}