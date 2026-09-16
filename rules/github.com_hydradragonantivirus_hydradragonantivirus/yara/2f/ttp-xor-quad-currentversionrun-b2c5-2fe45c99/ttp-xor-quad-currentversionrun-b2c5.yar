rule TTP_XOR_QUAD_CurrentVersionRun_b2c5 {
  strings:
    $key_b2c5 = { e1 aa [2] c5 a4 [2] ee 88 [2] c0 aa [2] d4 b1 [2] db ab [2] c5 b6 [2] c7 b7 [2] dc b1 [2] c0 b6 [2] dc 99 }

  condition:
    any of them
}