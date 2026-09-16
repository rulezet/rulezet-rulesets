rule TTP_XOR_QUAD_CurrentVersionRun_94d9 {
  strings:
    $key_94d9 = { c7 b6 [2] e3 b8 [2] c8 94 [2] e6 b6 [2] f2 ad [2] fd b7 [2] e3 aa [2] e1 ab [2] fa ad [2] e6 aa [2] fa 85 }

  condition:
    any of them
}