rule TTP_XOR_QUAD_CurrentVersionRun_88c4 {
  strings:
    $key_88c4 = { db ab [2] ff a5 [2] d4 89 [2] fa ab [2] ee b0 [2] e1 aa [2] ff b7 [2] fd b6 [2] e6 b0 [2] fa b7 [2] e6 98 }

  condition:
    any of them
}