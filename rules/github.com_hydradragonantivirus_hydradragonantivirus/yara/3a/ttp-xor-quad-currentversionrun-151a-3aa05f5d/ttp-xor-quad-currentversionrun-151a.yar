rule TTP_XOR_QUAD_CurrentVersionRun_151a {
  strings:
    $key_151a = { 46 75 [2] 62 7b [2] 49 57 [2] 67 75 [2] 73 6e [2] 7c 74 [2] 62 69 [2] 60 68 [2] 7b 6e [2] 67 69 [2] 7b 46 }

  condition:
    any of them
}