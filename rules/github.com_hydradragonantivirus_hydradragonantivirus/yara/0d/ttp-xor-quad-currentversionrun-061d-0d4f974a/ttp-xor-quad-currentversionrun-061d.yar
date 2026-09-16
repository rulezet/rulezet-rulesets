rule TTP_XOR_QUAD_CurrentVersionRun_061d {
  strings:
    $key_061d = { 55 72 [2] 71 7c [2] 5a 50 [2] 74 72 [2] 60 69 [2] 6f 73 [2] 71 6e [2] 73 6f [2] 68 69 [2] 74 6e [2] 68 41 }

  condition:
    any of them
}