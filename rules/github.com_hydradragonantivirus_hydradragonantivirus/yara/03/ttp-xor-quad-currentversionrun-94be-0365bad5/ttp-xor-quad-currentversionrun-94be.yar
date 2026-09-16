rule TTP_XOR_QUAD_CurrentVersionRun_94be {
  strings:
    $key_94be = { c7 d1 [2] e3 df [2] c8 f3 [2] e6 d1 [2] f2 ca [2] fd d0 [2] e3 cd [2] e1 cc [2] fa ca [2] e6 cd [2] fa e2 }

  condition:
    any of them
}