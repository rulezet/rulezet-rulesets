rule TTP_XOR_MULT_DOSStub_ee99 {
  strings:
    $key_ee99 = { ba f1 [2] ce e9 [2] 89 eb [2] ce fa [2] 80 f6 [2] 8c fc [2] 9b f7 [2] 80 b9 [2] bd }

  condition:
    any of them
}