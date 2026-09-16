rule TTP_XOR_QUAD_CurrentVersionRun_281f {
  strings:
    $key_281f = { 7b 70 [2] 5f 7e [2] 74 52 [2] 5a 70 [2] 4e 6b [2] 41 71 [2] 5f 6c [2] 5d 6d [2] 46 6b [2] 5a 6c [2] 46 43 }

  condition:
    any of them
}