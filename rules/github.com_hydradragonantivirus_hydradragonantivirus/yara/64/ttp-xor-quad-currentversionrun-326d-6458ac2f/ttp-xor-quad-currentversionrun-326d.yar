rule TTP_XOR_QUAD_CurrentVersionRun_326d {
  strings:
    $key_326d = { 61 02 [2] 45 0c [2] 6e 20 [2] 40 02 [2] 54 19 [2] 5b 03 [2] 45 1e [2] 47 1f [2] 5c 19 [2] 40 1e [2] 5c 31 }

  condition:
    any of them
}