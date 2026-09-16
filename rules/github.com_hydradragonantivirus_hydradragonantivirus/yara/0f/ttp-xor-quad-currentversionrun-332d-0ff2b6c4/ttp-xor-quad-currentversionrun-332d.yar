rule TTP_XOR_QUAD_CurrentVersionRun_332d {
  strings:
    $key_332d = { 60 42 [2] 44 4c [2] 6f 60 [2] 41 42 [2] 55 59 [2] 5a 43 [2] 44 5e [2] 46 5f [2] 5d 59 [2] 41 5e [2] 5d 71 }

  condition:
    any of them
}