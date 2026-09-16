rule TTP_XOR_QUAD_CurrentVersionRun_264a {
  strings:
    $key_264a = { 75 25 [2] 51 2b [2] 7a 07 [2] 54 25 [2] 40 3e [2] 4f 24 [2] 51 39 [2] 53 38 [2] 48 3e [2] 54 39 [2] 48 16 }

  condition:
    any of them
}