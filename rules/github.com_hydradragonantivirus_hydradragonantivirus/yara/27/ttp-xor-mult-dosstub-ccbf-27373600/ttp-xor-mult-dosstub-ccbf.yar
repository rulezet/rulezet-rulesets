rule TTP_XOR_MULT_DOSStub_ccbf {
  strings:
    $key_ccbf = { 98 d7 [2] ec cf [2] ab cd [2] ec dc [2] a2 d0 [2] ae da [2] b9 d1 [2] a2 9f [2] 9f }

  condition:
    any of them
}