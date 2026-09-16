rule TTP_XOR_QUAD_CurrentVersionRun_304a {
  strings:
    $key_304a = { 63 25 [2] 47 2b [2] 6c 07 [2] 42 25 [2] 56 3e [2] 59 24 [2] 47 39 [2] 45 38 [2] 5e 3e [2] 42 39 [2] 5e 16 }

  condition:
    any of them
}