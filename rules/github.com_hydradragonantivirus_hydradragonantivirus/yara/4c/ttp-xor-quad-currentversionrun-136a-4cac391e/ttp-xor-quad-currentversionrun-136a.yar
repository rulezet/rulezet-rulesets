rule TTP_XOR_QUAD_CurrentVersionRun_136a {
  strings:
    $key_136a = { 40 05 [2] 64 0b [2] 4f 27 [2] 61 05 [2] 75 1e [2] 7a 04 [2] 64 19 [2] 66 18 [2] 7d 1e [2] 61 19 [2] 7d 36 }

  condition:
    any of them
}