rule TTP_XOR_QUAD_CurrentVersionRun_151d {
  strings:
    $key_151d = { 46 72 [2] 62 7c [2] 49 50 [2] 67 72 [2] 73 69 [2] 7c 73 [2] 62 6e [2] 60 6f [2] 7b 69 [2] 67 6e [2] 7b 41 }

  condition:
    any of them
}