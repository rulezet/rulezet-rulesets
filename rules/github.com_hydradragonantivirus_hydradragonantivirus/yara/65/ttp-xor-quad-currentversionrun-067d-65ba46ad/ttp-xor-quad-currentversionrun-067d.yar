rule TTP_XOR_QUAD_CurrentVersionRun_067d {
  strings:
    $key_067d = { 55 12 [2] 71 1c [2] 5a 30 [2] 74 12 [2] 60 09 [2] 6f 13 [2] 71 0e [2] 73 0f [2] 68 09 [2] 74 0e [2] 68 21 }

  condition:
    any of them
}