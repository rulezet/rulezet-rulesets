rule TTP_XOR_QUAD_CurrentVersionRun_065d {
  strings:
    $key_065d = { 55 32 [2] 71 3c [2] 5a 10 [2] 74 32 [2] 60 29 [2] 6f 33 [2] 71 2e [2] 73 2f [2] 68 29 [2] 74 2e [2] 68 01 }

  condition:
    any of them
}