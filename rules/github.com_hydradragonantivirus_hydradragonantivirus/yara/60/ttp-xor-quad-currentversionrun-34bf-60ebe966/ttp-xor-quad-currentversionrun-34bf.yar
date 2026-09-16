rule TTP_XOR_QUAD_CurrentVersionRun_34bf {
  strings:
    $key_34bf = { 67 d0 [2] 43 de [2] 68 f2 [2] 46 d0 [2] 52 cb [2] 5d d1 [2] 43 cc [2] 41 cd [2] 5a cb [2] 46 cc [2] 5a e3 }

  condition:
    any of them
}