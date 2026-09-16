rule TTP_XOR_QUAD_CurrentVersionRun_dad9 {
  strings:
    $key_dad9 = { 89 b6 [2] ad b8 [2] 86 94 [2] a8 b6 [2] bc ad [2] b3 b7 [2] ad aa [2] af ab [2] b4 ad [2] a8 aa [2] b4 85 }

  condition:
    any of them
}