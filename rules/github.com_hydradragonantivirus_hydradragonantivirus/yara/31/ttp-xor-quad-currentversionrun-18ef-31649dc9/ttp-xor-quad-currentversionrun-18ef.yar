rule TTP_XOR_QUAD_CurrentVersionRun_18ef {
  strings:
    $key_18ef = { 4b 80 [2] 6f 8e [2] 44 a2 [2] 6a 80 [2] 7e 9b [2] 71 81 [2] 6f 9c [2] 6d 9d [2] 76 9b [2] 6a 9c [2] 76 b3 }

  condition:
    any of them
}