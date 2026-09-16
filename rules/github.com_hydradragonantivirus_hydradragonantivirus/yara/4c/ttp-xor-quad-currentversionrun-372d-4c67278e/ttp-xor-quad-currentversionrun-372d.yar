rule TTP_XOR_QUAD_CurrentVersionRun_372d {
  strings:
    $key_372d = { 64 42 [2] 40 4c [2] 6b 60 [2] 45 42 [2] 51 59 [2] 5e 43 [2] 40 5e [2] 42 5f [2] 59 59 [2] 45 5e [2] 59 71 }

  condition:
    any of them
}