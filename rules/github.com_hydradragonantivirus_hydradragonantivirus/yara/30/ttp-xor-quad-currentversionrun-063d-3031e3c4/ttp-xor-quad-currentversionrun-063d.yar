rule TTP_XOR_QUAD_CurrentVersionRun_063d {
  strings:
    $key_063d = { 55 52 [2] 71 5c [2] 5a 70 [2] 74 52 [2] 60 49 [2] 6f 53 [2] 71 4e [2] 73 4f [2] 68 49 [2] 74 4e [2] 68 61 }

  condition:
    any of them
}