rule TTP_XOR_QUAD_CurrentVersionRun_071c {
  strings:
    $key_071c = { 54 73 [2] 70 7d [2] 5b 51 [2] 75 73 [2] 61 68 [2] 6e 72 [2] 70 6f [2] 72 6e [2] 69 68 [2] 75 6f [2] 69 40 }

  condition:
    any of them
}