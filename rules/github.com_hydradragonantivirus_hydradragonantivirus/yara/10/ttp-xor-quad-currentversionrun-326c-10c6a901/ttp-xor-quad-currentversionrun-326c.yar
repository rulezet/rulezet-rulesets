rule TTP_XOR_QUAD_CurrentVersionRun_326c {
  strings:
    $key_326c = { 61 03 [2] 45 0d [2] 6e 21 [2] 40 03 [2] 54 18 [2] 5b 02 [2] 45 1f [2] 47 1e [2] 5c 18 [2] 40 1f [2] 5c 30 }

  condition:
    any of them
}