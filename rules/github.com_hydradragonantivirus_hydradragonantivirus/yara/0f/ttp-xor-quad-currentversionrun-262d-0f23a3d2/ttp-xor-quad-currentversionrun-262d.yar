rule TTP_XOR_QUAD_CurrentVersionRun_262d {
  strings:
    $key_262d = { 75 42 [2] 51 4c [2] 7a 60 [2] 54 42 [2] 40 59 [2] 4f 43 [2] 51 5e [2] 53 5f [2] 48 59 [2] 54 5e [2] 48 71 }

  condition:
    any of them
}