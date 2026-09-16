rule TTP_XOR_QUAD_CurrentVersionRun_626a {
  strings:
    $key_626a = { 31 05 [2] 15 0b [2] 3e 27 [2] 10 05 [2] 04 1e [2] 0b 04 [2] 15 19 [2] 17 18 [2] 0c 1e [2] 10 19 [2] 0c 36 }

  condition:
    any of them
}