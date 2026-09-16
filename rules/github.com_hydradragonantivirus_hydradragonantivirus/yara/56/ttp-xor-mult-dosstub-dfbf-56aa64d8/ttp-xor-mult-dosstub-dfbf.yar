rule TTP_XOR_MULT_DOSStub_dfbf {
  strings:
    $key_dfbf = { 8b d7 [2] ff cf [2] b8 cd [2] ff dc [2] b1 d0 [2] bd da [2] aa d1 [2] b1 9f [2] 8c }

  condition:
    any of them
}