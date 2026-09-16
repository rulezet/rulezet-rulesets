rule TTP_XOR_QUAD_CurrentVersionRun_9adc {
  strings:
    $key_9adc = { c9 b3 [2] ed bd [2] c6 91 [2] e8 b3 [2] fc a8 [2] f3 b2 [2] ed af [2] ef ae [2] f4 a8 [2] e8 af [2] f4 80 }

  condition:
    any of them
}