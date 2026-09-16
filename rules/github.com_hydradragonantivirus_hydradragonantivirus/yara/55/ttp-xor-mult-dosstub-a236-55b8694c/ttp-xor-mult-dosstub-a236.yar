rule TTP_XOR_MULT_DOSStub_a236 {
  strings:
    $key_a236 = { f6 5e [2] 82 46 [2] c5 44 [2] 82 55 [2] cc 59 [2] c0 53 [2] d7 58 [2] cc 16 [2] f1 }

  condition:
    any of them
}