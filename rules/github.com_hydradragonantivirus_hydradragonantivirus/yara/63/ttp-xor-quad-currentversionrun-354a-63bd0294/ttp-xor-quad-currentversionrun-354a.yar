rule TTP_XOR_QUAD_CurrentVersionRun_354a {
  strings:
    $key_354a = { 66 25 [2] 42 2b [2] 69 07 [2] 47 25 [2] 53 3e [2] 5c 24 [2] 42 39 [2] 40 38 [2] 5b 3e [2] 47 39 [2] 5b 16 }

  condition:
    any of them
}