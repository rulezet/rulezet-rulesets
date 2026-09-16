rule TTP_XOR_QUAD_CurrentVersionRun_297b {
  strings:
    $key_297b = { 7a 14 [2] 5e 1a [2] 75 36 [2] 5b 14 [2] 4f 0f [2] 40 15 [2] 5e 08 [2] 5c 09 [2] 47 0f [2] 5b 08 [2] 47 27 }

  condition:
    any of them
}