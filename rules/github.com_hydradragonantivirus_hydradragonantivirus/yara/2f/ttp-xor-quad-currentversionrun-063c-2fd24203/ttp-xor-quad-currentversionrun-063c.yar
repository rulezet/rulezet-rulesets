rule TTP_XOR_QUAD_CurrentVersionRun_063c {
  strings:
    $key_063c = { 55 53 [2] 71 5d [2] 5a 71 [2] 74 53 [2] 60 48 [2] 6f 52 [2] 71 4f [2] 73 4e [2] 68 48 [2] 74 4f [2] 68 60 }

  condition:
    any of them
}