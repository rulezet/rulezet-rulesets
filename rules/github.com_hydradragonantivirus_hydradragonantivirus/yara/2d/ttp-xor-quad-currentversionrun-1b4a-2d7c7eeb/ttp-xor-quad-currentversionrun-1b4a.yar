rule TTP_XOR_QUAD_CurrentVersionRun_1b4a {
  strings:
    $key_1b4a = { 48 25 [2] 6c 2b [2] 47 07 [2] 69 25 [2] 7d 3e [2] 72 24 [2] 6c 39 [2] 6e 38 [2] 75 3e [2] 69 39 [2] 75 16 }

  condition:
    any of them
}