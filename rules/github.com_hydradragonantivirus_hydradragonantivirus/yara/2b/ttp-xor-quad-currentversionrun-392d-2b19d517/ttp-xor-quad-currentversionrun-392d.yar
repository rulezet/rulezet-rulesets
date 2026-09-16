rule TTP_XOR_QUAD_CurrentVersionRun_392d {
  strings:
    $key_392d = { 6a 42 [2] 4e 4c [2] 65 60 [2] 4b 42 [2] 5f 59 [2] 50 43 [2] 4e 5e [2] 4c 5f [2] 57 59 [2] 4b 5e [2] 57 71 }

  condition:
    any of them
}