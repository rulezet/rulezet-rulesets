rule TTP_XOR_QUAD_CurrentVersionRun_063a {
  strings:
    $key_063a = { 55 55 [2] 71 5b [2] 5a 77 [2] 74 55 [2] 60 4e [2] 6f 54 [2] 71 49 [2] 73 48 [2] 68 4e [2] 74 49 [2] 68 66 }

  condition:
    any of them
}