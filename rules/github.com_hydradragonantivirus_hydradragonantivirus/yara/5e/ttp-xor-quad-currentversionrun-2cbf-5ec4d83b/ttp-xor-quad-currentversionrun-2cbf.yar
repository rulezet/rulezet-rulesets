rule TTP_XOR_QUAD_CurrentVersionRun_2cbf {
  strings:
    $key_2cbf = { 7f d0 [2] 5b de [2] 70 f2 [2] 5e d0 [2] 4a cb [2] 45 d1 [2] 5b cc [2] 59 cd [2] 42 cb [2] 5e cc [2] 42 e3 }

  condition:
    any of them
}