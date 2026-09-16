rule TTP_XOR_MULT_DOSStub_9db2 {
  strings:
    $key_9db2 = { c9 da [2] bd c2 [2] fa c0 [2] bd d1 [2] f3 dd [2] ff d7 [2] e8 dc [2] f3 92 [2] ce }

  condition:
    any of them
}