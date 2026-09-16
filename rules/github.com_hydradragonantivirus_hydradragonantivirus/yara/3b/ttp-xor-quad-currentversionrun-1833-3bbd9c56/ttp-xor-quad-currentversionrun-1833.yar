rule TTP_XOR_QUAD_CurrentVersionRun_1833 {
  strings:
    $key_1833 = { 4b 5c [2] 6f 52 [2] 44 7e [2] 6a 5c [2] 7e 47 [2] 71 5d [2] 6f 40 [2] 6d 41 [2] 76 47 [2] 6a 40 [2] 76 6f }

  condition:
    any of them
}