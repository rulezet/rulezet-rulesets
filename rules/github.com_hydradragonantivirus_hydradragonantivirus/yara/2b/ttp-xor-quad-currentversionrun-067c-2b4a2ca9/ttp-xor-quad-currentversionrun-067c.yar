rule TTP_XOR_QUAD_CurrentVersionRun_067c {
  strings:
    $key_067c = { 55 13 [2] 71 1d [2] 5a 31 [2] 74 13 [2] 60 08 [2] 6f 12 [2] 71 0f [2] 73 0e [2] 68 08 [2] 74 0f [2] 68 20 }

  condition:
    any of them
}