rule TTP_XOR_QUAD_CurrentVersionRun_442d {
  strings:
    $key_442d = { 17 42 [2] 33 4c [2] 18 60 [2] 36 42 [2] 22 59 [2] 2d 43 [2] 33 5e [2] 31 5f [2] 2a 59 [2] 36 5e [2] 2a 71 }

  condition:
    any of them
}