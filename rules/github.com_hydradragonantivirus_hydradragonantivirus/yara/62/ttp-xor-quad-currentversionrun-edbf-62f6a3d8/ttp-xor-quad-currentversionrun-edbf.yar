rule TTP_XOR_QUAD_CurrentVersionRun_edbf {
  strings:
    $key_edbf = { be d0 [2] 9a de [2] b1 f2 [2] 9f d0 [2] 8b cb [2] 84 d1 [2] 9a cc [2] 98 cd [2] 83 cb [2] 9f cc [2] 83 e3 }

  condition:
    any of them
}